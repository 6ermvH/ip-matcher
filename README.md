# ip-matcher-iplocate

Утилита для поиска IP-подсетей хостеров, пересекающихся с allow-list'ом
(например, whitelist'ом мобильных операторов России).

## Почему «iplocate» в названии, но данные с bgp.he.net

Изначально хотели парсить [iplocate.io](https://www.iplocate.io) — у них
есть страницы по хостерам с готовыми CIDR-листами. Но iplocate **за
Cloudflare JS-challenge** — без headless-браузера не пройти.

[bgp.he.net](https://bgp.he.net) отдаёт те же данные (ASN → префиксы)
обычным GET-ом, бесплатно, без блокировок. По нему и работаем.

## Сборка и запуск

```bash
go build -o bin/ip-matcher .

# Самый простой случай: подсети Timeweb, пересекающиеся с allow-list
./bin/ip-matcher --provider timeweb --allow allowed_ips.txt

# Несколько ASN явно (если хостера нет в пресетах)
./bin/ip-matcher --asn 9123,210976 --allow allowed_ips.txt

# Все префиксы провайдера, без фильтра
./bin/ip-matcher --provider selectel --all

# С определением города через ip-api.com (~1 сек на подсеть)
./bin/ip-matcher --provider timeweb --allow ./allowed_ips.txt --geoip

# JSON для дальнейшей обработки
./bin/ip-matcher --provider timeweb --allow ./allowed_ips.txt --json

# Список доступных пресетов
./bin/ip-matcher --list-providers
```

## Пресеты ASN

| Хостер | ASN |
| --- | --- |
| timeweb | 9123, 210976 |
| selectel | 49505, 50340 |
| vk | 47764, 47542, 28709 |
| yandex | 200350, 13238, 208722 |
| reg | 197695 |
| beget | 198610 |
| firstvds | 29182 |
| hostkey | 395839, 57043 |
| aeza | 210644 |

Если нужного хостера нет в списке — найди ASN на [bgp.he.net](https://bgp.he.net)
и передай через `--asn`.

## Формат allow-list

По строке IP или CIDR. `#` — комментарий. Одиночные IP трактуются как `/32`.

```
# allowed
185.91.52.0/24
46.149.66.0/24
8.8.8.8
```

## Зависимости

- Только stdlib. Сборка: `go build`. Бинарь ~5 МБ.

## Лицензия

MIT.
