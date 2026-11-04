# HOWTO (macOS, Intel): установка и тестирование клиента sshtun

Порт клиента vpn_over_ssh на macOS. Полный функционал Linux-версии:
full-tunnel через SSH (ssh -w / utun), исключения (exclude), принудительные
маршруты (include), автогенерация по AS/странам, профили серверов
(`server add/use/rename`), служба автозапуска/досмотра (launchd).

## Как это устроено (отличия от Linux)

- **Data-plane — собственный Go-бинарь** (`sshtun_macos_client/sshtun-macos-tun`,
  кросс-сборка Linux→darwin, лежит в репо и копируется installer'ом в
  /opt): реализует wire-протокол `tun@openssh.com` в userspace поверх
  x/crypto/ssh и управляет utun напрямую через сисколлы. Причина: ни Apple
  ssh, ни portable OpenSSH **вообще не умеют** utun (проверено: «Tunnel
  device open failed»; в openssh-portable нет utun-кода). Фолбэк «ssh -w»
  в бэкенде на macOS неработоспособен — бинарь обязателен.
- **Маршрутная политика — pfctl**, а не policy-routing таблицы: exclude/
  include префиксы живут в pf-таблицах (~12k+ записей за секунды), include
  идёт `route-to` в utun, catch-all — двумя полу-default'ами в таблице
  маршрутизации (`0.0.0.0/1` + `128.0.0.0/1` через peer utun; macOS
  route(8) не ест CIDR-форму `/1` — только `-netmask 128.0.0.0`).
  Для самого ssh-соединения бэкенд ставит **хост-маршрут /32 до сервера
  через дефолтный шлюз** — иначе /1'ы перехватывают и его.
- Семантика префиксов та же: LPM, на равных длинах include побеждает
  exclude (порядок quick-правил).
- **DNS: scutil** (networksetup отказывает демонам на macOS 15+), старые
  значения сохраняются в state и восстанавливаются при stop.
- Блок IPv6-трафика — правилом pf (вместо blackhole-маршрутов).
- State: `/var/run/sshtun` (аналог `/run/sshtun`).
- Требование: **bash >= 4.3** (системный bash 3.2 macOS не подходит).
  Все root-операции идут через root-хелпер `/opt/sshtun_client/sshtun-root`
  (единственная NOPASSWD-команда в sudoers); прямого «sudo bash» бэкенд
  не вызывает никогда.

## 0. Требования

- macOS Sonoma/Sequoia (Intel).
- **bash >= 4.3** — системный bash 3.2 не подходит (nameref/assoc-arrays).
  Без brew, без root (нужен Xcode CLT):
  ```bash
  bash prepare_macos.sh   # bash + LibreSSL + OpenSSH -> ~/sshtun-tools
  ```
  (если brew установлен, подойдёт `brew install bash openssh`.)
- `xcode-select --install` (python3/dig — из CLT).
- Data-plane-бинарь `sshtun-macos-tun` идёт в репозитории (кросс-сборка
  `CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build`); installer кладёт его
  в /opt/sshtun_client. Свежая сборка по LAN: scp в `~/sshtun-tools/bin/`
  (бэкенд ищет сначала там — обновление без root).
- Установщик сам найдёт подходящие bash/ssh и запишет пути в
  `/opt/sshtun_client/env.conf`; шим `/usr/local/bin/sshtun` жёстко
  привязан к нужному bash.

## 1. Установка

```bash
git clone https://github.com/woldemar/vpn_over_ssh.git ~/GIT/vpn_over_ssh
cd ~/GIT/vpn_over_ssh
git checkout <ветка/тег с macOS-портом>
sudo bash install_macos.sh install
```

Проверка: `sshtun --help` (через symlink `/usr/local/bin/sshtun`).

## 2. Ключ и сервер

```bash
ssh-keygen -t ed25519 -f ~/.ssh/sshtun_ed25519 -N "" -C "$(whoami)-$(hostname)"
# публичный ключ (~/.ssh/sshtun_ed25519.pub) добавить на сервер:
cat ~/.ssh/sshtun_ed25519.pub   # -> в /opt/sshtun_pool/authorized_keys на сервере

sshtun server add fin <адрес-сервера> -- "основной"
sshtun fin                      # сокращение от 'server use fin'
```

Если сервер живёт не в стандартной адресации/диапазоне — те же опции, что
на Linux: `--tun-start/--tun-end/--net-a/--net-b`.

## 3. Первый подъём и проверка

```bash
sshtun up
sshtun status
# ожидается: Status: running, TUN: utunN, Client IP 10.250.x.x,
# Policy: pf anchor com.sshtun

curl -4 ifconfig.me                 # IP сервера
curl -s -o /dev/null -w '%{http_code}\n' https://kimi.ai   # exclude-AS работает
route -n get default                # default route НЕ изменился (pf перехватывает)
sudo pfctl -a com.sshtun -s rules   # наши правила загружены
sudo pfctl -a com.sshtun -t sshtun_excludes -T show | wc -l   # ~12k префиксов
scutil --dns | head                 # DNS = 1.1.1.1/8.8.8.8
```

## 4. Тесты маршрутной политики

```bash
# exclude: TEST-NET идёт напрямую (не через tun)
sshtun exclude add 203.0.113.0/24 -- тест
sudo pfctl -a com.sshtun -t sshtun_excludes -T show | grep 203.0.113.0/24
sshtun exclude del 203.0.113.0/24

# include побеждает exclude на равном префиксе
sshtun include add 203.0.113.7
sudo pfctl -a com.sshtun -t sshtun_includes -T show | grep 203.0.113.7/32
sshtun include del 203.0.113.7

# fetch AS / страны (те же команды, что на Linux)
sshtun fetch-country ru
sshtun refresh
```

## 5. Служба (launchd): досмотр и автостарт

```bash
# включить досмотр (KeepAlive: падение ssh/обрыв/сон -> переподъём)
sudo /opt/sshtun_client/sshtun-root service-start   # bootout+bootstrap
sshtun down        # идёт через launchctl bootout (маркер SUPERVISED=1)

# автостарт при загрузке (после этого служба грузится сама при каждой загрузке)
sudo defaults write /Library/LaunchDaemons/com.sshtun.client.plist RunAtLoad -bool true

# выключить
sudo /opt/sshtun_client/sshtun-root service-stop    # или: launchctl bootout system/com.sshtun.client

tail -f /var/log/sshtun.log
```

Служба идёт **от root**: пути к данным и ключу зашиты в plist
(`EXCLUDES_DIR`/`KEY_FILE`), бинарь data-plane ищется в
`/opt/sshtun_client` (и в `sshtun_macos_client/` рядом с репозиторием).

## 6. Сон ноутбука (главный сценарий)

```bash
# служба загружена, туннель работает
pmset sleepnow                  # или закрыть крышку
# разбудить
sshtun status                   # поднялся сам (KeepAlive)
```

## 7. Диагностика

```bash
sshtun doctor                   # state, pf (rules/таблицы/счётчики), utun, DNS
sudo /opt/sshtun_client/sshtun-root backend-run pfprobe
                                # маршруты, pf states, счётчики правил, forwarding
sudo pfctl -s info              # pf включён?
cat /etc/pf.conf | grep sshtun  # anchor "com.sshtun" на месте?
sudo pfctl -a com.sshtun -s rules
tail -50 /var/log/sshtun.log
sshtun cleanup                  # снести остатки после сбоев
```

Типичные проблемы:
- `pfctl -e не удался` → в `/etc/pf.conf` нет `anchor "com.sshtun"`;
  переустановите: `sudo bash install_macos.sh reinstall`.
- `utun не появился` → смотреть `sudo cat /var/run/sshtun/ssh.last.log`
  (обычно ключ не авторизован на сервере или пул tun сервера не накрывает
  запрошенный номер).
- DNS не восстановился после down → `networksetup -setdnsservers Wi-Fi Empty`
  (или значения из бэкапа в `sshtun doctor`).
- Туннель живёт ~90 с и умирает → проверьте `route -n get <IP-сервера>`:
  должен идти через физический шлюз, а НЕ через utun (bypass /32 ставит
  бэкенд; без него catch-all /1-хавает сам ssh-поток).

## 8. Чек-лист готовности порта (пройден 04.11.2026, macOS 15.8.2 Intel)

- [x] `sshtun up/down/restart/status/doctor` работают на macOS (Intel)
- [x] full-tunnel: `curl ifconfig.me` показывает сервер; `route -n get default` НЕ изменён
- [x] exclude/include: pf-таблицы обновляются без перезапуска (§4)
- [x] DNS: `scutil --dns` = 1.1.1.1/8.8.8.8 при работе; восстановлены после down
- [x] fetch/refresh/--remove: токены и `generated/` как на Linux
- [x] мультисервер: `server add/use/rename`, сокращение `sshtun fin`
- [x] служба: kill ssh → рестарт; `sshtun down` без рестарта (§5)
- [x] сон → самовосстановление (§6)
- [x] `install/uninstall/reinstall`: файлы, plist, anchor; данные не теряются
- [x] лог службы: `tail -f /var/log/sshtun.log`
