// ip-matcher-iplocate — утилита для поиска IP-подсетей хостеров, пересекающихся
// с allow-list'ом (например, whitelist'ом мобильных операторов).
//
// Источник BGP-данных: bgp.he.net (открытый веб). Изначально планировалось
// парсить iplocate.io, но он за Cloudflare JS-challenge — без headless-браузера
// не пройти. bgp.he.net даёт те же данные (ASN → prefixes) и бесплатно.
//
// Опциональное обогащение geoip через ip-api.com (45 req/min без ключа).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// providerASNs — пресеты для популярных российских хостеров.
// При желании можно передать любые ASN через --asn.
var providerASNs = map[string][]int{
	"timeweb":   {9123, 210976},
	"selectel":  {49505, 50340},
	"vk":        {47764, 47542, 28709},
	"yandex":    {200350, 13238, 208722},
	"reg":       {197695},
	"beget":     {198610},
	"firstvds":  {29182},
	"hostkey":   {395839, 57043},
	"aeza":      {210644},
}

func main() {
	var (
		provider     = flag.String("provider", "", "Пресет хостера (timeweb|selectel|vk|yandex|reg|beget|firstvds|hostkey|aeza)")
		asnList      = flag.String("asn", "", "ASN через запятую (например 9123,210976). Если задан, перекрывает --provider")
		allowPath    = flag.String("allow", "", "Файл с allow-list (по строке IP или CIDR, # — комментарий)")
		jsonOut      = flag.Bool("json", false, "JSON-вывод")
		showAll      = flag.Bool("all", false, "Показывать все префиксы, а не только matched")
		enrichGeoIP  = flag.Bool("geoip", false, "Дёрнуть ip-api.com для определения города (медленно, 1 IP/сек)")
		geoIPSample  = flag.Int("geoip-sample", 1, "Сколько IP из подсети опрашивать для geoip (1 хватает)")
		timeoutFlag  = flag.Duration("timeout", 15*time.Second, "HTTP timeout на запрос к bgp.he.net")
		listProviders = flag.Bool("list-providers", false, "Показать пресеты хостеров и выйти")
	)
	flag.Parse()

	if *listProviders {
		for _, name := range sortedKeys(providerASNs) {
			fmt.Printf("  %-10s  ASN: %v\n", name, providerASNs[name])
		}
		return
	}

	asns, err := resolveASNs(*provider, *asnList)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	httpClient := &http.Client{Timeout: *timeoutFlag}

	allPrefixes, err := fetchPrefixes(ctx, httpClient, asns)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "fetched %d unique prefixes from %d ASN(s)\n", len(allPrefixes), len(asns))

	var allow []netip.Prefix
	if *allowPath != "" {
		allow, err = loadPrefixes(*allowPath)
		if err != nil {
			fatal(fmt.Errorf("читаю allow-list: %w", err))
		}
		fmt.Fprintf(os.Stderr, "loaded %d prefixes from allow-list\n", len(allow))
	}

	type match struct {
		Prefix string `json:"prefix"`
		City   string `json:"city,omitempty"`
		Region string `json:"region,omitempty"`
		ASN    int    `json:"asn,omitempty"`
	}
	var out []match
	for _, p := range allPrefixes {
		matched := allow == nil || intersectAny(p, allow)
		if !matched && !*showAll {
			continue
		}
		out = append(out, match{Prefix: p.String()})
	}

	if *enrichGeoIP {
		fmt.Fprintf(os.Stderr, "обогащаю %d подсетей через ip-api.com (~%ds)...\n", len(out), len(out)*(*geoIPSample))
		for i := range out {
			city, region, asn := lookupGeo(ctx, httpClient, mustFirstIP(out[i].Prefix), *geoIPSample)
			out[i].City = city
			out[i].Region = region
			out[i].ASN = asn
			time.Sleep(1400 * time.Millisecond) // под лимит 45 req/min
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	fmt.Printf("matched=%d / total=%d\n", len(out), len(allPrefixes))
	for _, m := range out {
		if m.City != "" {
			fmt.Printf("  %-20s  %s, %s\n", m.Prefix, m.City, m.Region)
		} else {
			fmt.Printf("  %s\n", m.Prefix)
		}
	}
}

func resolveASNs(provider, asnList string) ([]int, error) {
	if asnList != "" {
		var out []int
		for _, s := range strings.Split(asnList, ",") {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil {
				return nil, fmt.Errorf("плохой ASN %q: %w", s, err)
			}
			out = append(out, n)
		}
		return out, nil
	}
	if provider == "" {
		return nil, errors.New("укажите --provider или --asn (см. --list-providers)")
	}
	asns, ok := providerASNs[strings.ToLower(provider)]
	if !ok {
		return nil, fmt.Errorf("неизвестный provider %q (--list-providers)", provider)
	}
	return asns, nil
}

func fetchPrefixes(ctx context.Context, h *http.Client, asns []int) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]struct{}{}
	cidrRE := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b`)
	for _, asn := range asns {
		url := fmt.Sprintf("https://bgp.he.net/AS%d", asn)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (ip-matcher-iplocate)")
		resp, err := h.Do(req)
		if err != nil {
			return nil, fmt.Errorf("AS%d: %w", asn, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("AS%d: HTTP %d", asn, resp.StatusCode)
		}
		for _, m := range cidrRE.FindAllString(string(body), -1) {
			if p, err := netip.ParsePrefix(m); err == nil {
				seen[p.Masked()] = struct{}{}
			}
		}
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func loadPrefixes(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path) // #nosec G304 -- путь от пользователя CLI
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// одиночный IP → /32
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out, sc.Err()
}

func intersectAny(p netip.Prefix, allow []netip.Prefix) bool {
	for _, a := range allow {
		if a.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if a.Bits() <= p.Bits() {
			if a.Contains(p.Addr()) {
				return true
			}
		} else if p.Contains(a.Addr()) {
			return true
		}
	}
	return false
}

func mustFirstIP(prefix string) string {
	p, _ := netip.ParsePrefix(prefix)
	return p.Addr().Next().String()
}

func lookupGeo(ctx context.Context, h *http.Client, ip string, _ int) (city, region string, asn int) {
	url := "http://ip-api.com/json/" + ip + "?fields=city,regionName,as,query,status,message"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := h.Do(req)
	if err != nil {
		return "", "", 0
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		City       string `json:"city"`
		RegionName string `json:"regionName"`
		AS         string `json:"as"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	if r.Status != "success" {
		return "", "", 0
	}
	asnNum := 0
	if r.AS != "" {
		_, _ = fmt.Sscanf(r.AS, "AS%d", &asnNum)
	}
	return r.City, r.RegionName, asnNum
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ошибка:", err)
	os.Exit(1)
}
