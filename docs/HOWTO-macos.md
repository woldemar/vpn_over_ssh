# HOWTO (macOS, Intel): установка и тестирование клиента sshtun

Порт клиента vpn_over_ssh на macOS. Полный функционал Linux-версии:
full-tunnel через SSH (ssh -w / utun), исключения (exclude), принудительные
маршруты (include), автогенерация по AS/странам, профили серверов
(`server add/use/rename`), служба автозапуска/досмотра (launchd).

## Как это устроено (отличия от Linux)

- Маршрутная политика — **pfctl**, а не policy-routing таблицы: exclude/include
  префиксы живут в pf-таблицах, catch-all идёт `route-to` в utun.
  Main routing table macOS не трогается вообще.
- Семантика префиксов та же: pf выбирает самый длинный префикс (LPM), на
  равных длинах include побеждает exclude (порядок quick-правил).
- DNS: `networksetup` per-service (Wi-Fi), старые значения сохраняются и
  восстанавливаются при stop.
- Блок IPv6-трафика — правилом pf (вместо blackhole-маршрутов).
- State: `/var/run/sshtun` (аналог `/run/sshtun`).
- Требование: **bash >= 4.3** (системный bash 3.2 macOS не подходит —
  обёртка использует nameref/ассоциативные массивы). Ставится через brew;
  launchd-окружение выставляет PATH с приоритетом brew.

## 0. Требования

- macOS Sonoma/Sequoia (Intel), brew установлен.
- `brew install bash` (>= 4.3), `xcode-select --install` (python3/dig).

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
# включить досмотр (KeepAlive: падение ssh -> переподъём ~секунды)
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sshtun.client.plist
sshtun down        # идёт через launchctl bootout (маркер SUPERVISED)

# автостарт при загрузке
sudo defaults write /Library/LaunchDaemons/com.sshtun.client.plist RunAtLoad -bool true

# выключить
sudo launchctl bootout system/com.sshtun.client

tail -f /var/log/sshtun.log
```

## 6. Сон ноутбука (главный сценарий)

```bash
# служба загружена, туннель работает
pmset sleepnow                  # или закрыть крышку
# разбудить
sshtun status                   # поднялся сам (KeepAlive)
```

## 7. Диагностика

```bash
sshtun doctor                   # state, pf, utun, DNS
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

## 8. Чек-лист готовности порта

- [ ] `sshtun up/down/restart/status/doctor` работают на macOS (Intel)
- [ ] full-tunnel: `curl ifconfig.me` показывает сервер; `route -n get default` НЕ изменён
- [ ] exclude/include: pf-таблицы обновляются без перезапуска (§4)
- [ ] DNS: `scutil --dns` = 1.1.1.1/8.8.8.8 при работе; восстановлены после down
- [ ] fetch/refresh/--remove: токены и `generated/` как на Linux
- [ ] мультисервер: `server add/use/rename`, сокращение `sshtun fin`
- [ ] служба: kill ssh → рестарт; `sshtun down` без рестарта (§5)
- [ ] сон → самовосстановление (§6)
- [ ] `install/uninstall/reinstall`: файлы, plist, anchor; данные не теряются
- [ ] лог службы: `tail -f /var/log/sshtun.log`
