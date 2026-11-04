# VPN over SSH

Проект реализует L3-туннель поверх обычного SSH с использованием OpenSSH TUN (`ssh -w` на Linux/Windows; на macOS — wire-протокол `tun@openssh.com` в userspace, т.к. ни Apple, ни portable OpenSSH utun не поддерживают). Сервер поднимает пул TUN-интерфейсов, клиенты случайно выбирают свободный `tunN`, подключаются по SSH и направляют трафик через зашифрованный SSH-канал.

Основная идея MVP: использовать стандартный OpenSSH вместо отдельного VPN-сервера. На сервере достаточно отдельного `sshd`-инстанса с `PermitTunnel point-to-point`, подготовленного пула `tun200..tun250` и NAT. На клиентах используются Linux shell-клиент, macOS-клиент (bash-бэкенд + собственный Go data-plane) или Windows Go/Wintun-клиент.

## Схема работы

```text
User workstation
    |
    | local TUN adapter
    |
Linux: sshtun_pool_client.sh
macOS: sshtun_macos.sh + Go data-plane (utun userspace)
Windows: sshtun_pool_client.exe + Wintun
    |
    | SSH TCP, tun@openssh.com / ssh -w N:N
    |
sshtun-pool-sshd на сервере
    |
    | tunN -> NAT -> WAN
    v
Internet / routed networks
```

По умолчанию используется пул `tun200..tun250` и адресация внутри `10.250.0.0/16` (пул выровнен с дефолтным клиентским диапазоном `TUN_START..TUN_END` — клиент просит у сервера устройство с тем же номером):

```text
tun200 -> server 10.250.0.1,   client 10.250.0.2
tun201 -> server 10.250.0.5,   client 10.250.0.6
tun250 -> server 10.250.0.201, client 10.250.0.202
```

Адреса выделяются парами по схеме `/30`-блоков. Клиенту не нужно заранее знать свой IP: он вычисляется из номера выбранного `tunN`.

## Что лежит в проекте

```text
.
├── CHANGELOG.md
├── docs/
│   ├── HOWTO.md                — инструкция по тестированию клиента (Linux)
│   ├── HOWTO-macos.md          — macOS-клиент: установка, тесты, служба (Intel и Apple Silicon)
│   └── SERVER-BBR.md           — пошаговый мануал: переключение сервера на BBR
├── examples/                   — шаблоны файлов маршрутной политики
│   ├── excludes.txt
│   ├── excludes-custom.txt
│   ├── excludes-as.txt
│   └── excludes-country.txt
├── install_client.sh           — установка/удаление/обновление Linux-клиента
├── install_macos.sh            — установка/удаление macOS-клиента (plist службы, sudoers, data-plane)
├── install_server.sh
├── prepare_macos.sh            — сборка bash>=4.3 + ssh в ~/sshtun-tools без brew (CLT)
├── sshtun_full.sh              — общая обёртка (Linux и macOS: выбор бэкенда по ОС)
├── sshtun_pool_client.sh       — Linux-бэкенд
├── sshtun_macos.sh             — macOS-бэкенд (pfctl, scutil, launchd)
├── sshtun_root.sh              — root-хелпер macOS (единственная NOPASSWD-команда)
├── sshtun_macos_client/        — Go data-plane macOS (tun@openssh.com в userspace;
│                                 бинарники amd64/arm64 идут в репозитории)
└── sshtun_pool_windows_client
    ├── README.md
    ├── build.ps1
    ├── go.mod
    ├── go.sum
    ├── cmd/sshtun_pool_client/main.go
    └── internal
        ├── admin
        ├── ipcalc
        ├── packetpump
        ├── routes
        ├── sshtransport
        └── wintun
```

Суть и причины изменений проекта — в [`CHANGELOG.md`](CHANGELOG.md).

### `install_server.sh`

Серверный установщик. Он:

- устанавливает зависимости;
- создаёт системного пользователя `sshvpn`;
- создаёт отдельную конфигурацию SSHD в `/opt/sshtun_pool/sshd_config`;
- создаёт отдельный systemd-сервис `sshtun-pool-sshd.service`;
- создаёт service `sshtun-pool-network.service` для подготовки TUN-пула и NAT;
- генерирует отдельный host key для SSH-TUN сервиса;
- включает `net.ipv4.ip_forward=1`;
- создаёт `tun200..tun250` (диапазон настраивается через `TUN_NUM_START` / `TUN_POOL_SIZE`; должен накрывать клиентский `TUN_START..TUN_END`);
- добавляет минимальные правила NAT/forwarding через WAN-интерфейс;
- директивы, которых нет в старом OpenSSH (`PermitListen none`, `PermitOpen none`), добавляет в graceful-режиме — установка не падает на OpenSSH < 7.8, например на Ubuntu 18.04.

Важно: это отдельный SSHD-инстанс на отдельном порту, а не изменение основного SSH на `22/tcp`.

### `sshtun_pool_client.sh`

Linux-клиент. Поддерживает:

- full-tunnel режим;
- split-tunnel режим;
- route/include/exclude CIDR;
- списки маршрутов из файлов;
- policy routing (как Tailscale/Netbird): маршруты живут в отдельных таблицах (`POLICY_TABLE_DIRECT=200`, `POLICY_TABLE_TUN=201`, правила с приоритетами 25100/25110), main-таблица не изменяется — `ip route` остаётся чистым даже с десятками тысяч префиксов;
- DNS через `resolvectl`;
- IPv6 blackhole для защиты от IPv6 leak;
- lock от параллельных стартов/остановок;
- cleanup старых управляемых `tunN`;
- работу с passphrase-protected ключами через `ssh-agent` или `--ask-passphrase`;
- режим `--foreground`: после старта процесс не выходит, а досматривает ssh —
  основа для systemd-службы (падение ssh → cleanup + exit 1 → рестарт;
  штатный stop → exit 0);
- `status`, `doctor`, `cleanup`.

Опционально установщики (`install_server.sh`, `install_client.sh`) умеют
выбирать алгоритм управления конгестией TCP машины (`TCP_CONGESTION_CONTROL=bbr|cubic`,
по умолчанию система не трогается). BBR снимает RTO-спайки SSH-туннеля на
шумных/теряющих путях — это sender-side алгоритм, полный эффект при включении
на обоих концах. См. раздел 7 [`docs/HOWTO.md`](docs/HOWTO.md).

### `install_client.sh`

Установщик Linux-клиента. Разделяет «репозиторий для разработки» и
«установленный клиент»: скрипты копируются в `/opt/sshtun_client/`, а в
`/usr/local/bin/` создаётся команда `sshtun` (symlink). Запускать из
репозитория больше не нужно.

```bash
sudo bash install_client.sh install      # установить или обновить копию
sudo bash install_client.sh update       # git pull + install
sudo bash install_client.sh reinstall    # переустановка
sudo bash install_client.sh uninstall    # убрать /opt, symlink, юнит и sysctl-файл congestion control (~/sshtun остаётся)
sudo bash install_client.sh uninstall --purge   # и данные ~/sshtun тоже
```

Опционально — выбор алгоритма управления конгестией TCP (`BBR`/`CUBIC`):
по умолчанию установщик систему не трогает. Подробности и замеры: раздел 7
[`docs/HOWTO.md`](docs/HOWTO.md).

```bash
sudo TCP_CONGESTION_CONTROL=bbr bash install_client.sh install    # включить BBR
sudo TCP_CONGESTION_CONTROL=cubic bash install_client.sh install  # откат к CUBIC
```

При первой установке создаёт `~/sshtun/` из шаблонов `examples/`
(существующие файлы не трогает). Также ставит systemd-юнит
`/etc/systemd/system/sshtun.service` **выключенным** — досмотр туннеля с
перезапуском при любом падении (сон, пропадание сети, внешний kill) и
опциональный автостарт при загрузке. Когда юнит установлен, обычный
`sshtun up` поднимает туннель **через службу** (это дефолт); прямой фоновый
запуск без досмотра остаётся только явным флагом: `sshtun up --background`.
Ручной `sshtun down`/`restart` при работающей службе автоматически идут
через `systemctl stop/restart`:

```bash
systemctl start sshtun     # туннель под досмотром systemd
systemctl stop sshtun      # штатная остановка (без рестарта)
systemctl enable sshtun    # автостарт при загрузке ПК
journalctl -u sshtun -f    # лог
```

Для службы ключ должен быть без passphrase (SSH BatchMode). Проверка и
сценарии: [`docs/HOWTO.md`](docs/HOWTO.md).

### macOS-клиент (`install_macos.sh`, `sshtun_macos.sh`)

Тот же контракт CLI/state и та же обёртка `sshtun`, что на Linux (она
выбирает бэкенд по ОС). Отличия: маршрутная политика через **pfctl**
(таблицы exclude/include + полу-default'ы 0.0.0.0/1 + 128.0.0.0/1 через
utun), DNS через **scutil**, блок IPv6 правилом pf, служба досмотра —
**launchd**. Транспорт — собственный **Go data-plane**
(`sshtun_macos_client/`, протокол `tun@openssh.com` в userspace): `ssh -w`
на macOS неработоспособен в принципе (ни Apple, ни portable OpenSSH не
поддерживают utun). Бинарники для Intel и Apple Silicon лежат в репозитории,
установщик выбирает по `uname -m`. Root-доступ — только через root-owned
хелпер `/opt/sshtun_client/sshtun-root` (единственная команда в
NOPASSWD-sudoers).

```bash
bash prepare_macos.sh                      # bash>=4.3 + ssh -> ~/sshtun-tools (без brew, нужен CLT)
sudo bash install_macos.sh install
sshtun up
sudo /opt/sshtun_client/sshtun-root service-start   # служба launchd (KeepAlive; переживает сон)
```

Полная инструкция, тесты и диагностика: [`docs/HOWTO-macos.md`](docs/HOWTO-macos.md).

### `sshtun_full.sh`

Обёртка над `sshtun_pool_client.sh` для постоянного режима «full-tunnel + исключения» (см. `CHANGELOG.md`). Поддерживает:

- `up` / `down` / `restart` / `status` / `doctor` / `cleanup`;
- файлы маршрутной политики в `~/sshtun/`:
  - `excludes.txt` — базовые исключения (RFC1918 и админские сети), трафик идёт напрямую;
  - `excludes-custom.txt` — пополняемый пользователем список исключений;
  - `excludes-as.txt` — источники-токены автономных систем (`AS9009`), по одному на строку; править руками или `fetch-as`;
  - `excludes-country.txt` — источники-токены стран по ISO-кодам (`ru`), править руками или `fetch-country`;
  - `generated/excludes-as.txt`, `generated/excludes-country.txt` — автоген: развёрнутые префиксы источников (не править; обновляются `refresh`, при `up` — автообновление не чаще раза в 12 ч, при отсутствии сети используется последний кэш);
  - `includes-force.txt` — принудительно «в туннель», приоритет над exclude-файлами;
- команды: `exclude add` / `exclude del` (пользовательские исключения), `include add` / `include del` (force-список) — обе пары принимают `-- комментарий`, он сохраняется в файле и виден в `list`; `fetch-as AS... [--irr] [--remove AS...]`, `fetch-country CC... [--remove CC...]`, `refresh` (перекачка автогенных списков), `list` (показ эффективной политики); устаревшие `add`/`del`/`force-add`/`force-del` работают как алиасы с подсказкой миграции;
- мультисервер: профили `~/sshtun/servers/<имя>.conf` (`server add NAME HOST [--port N] [--user U] [--key FILE] [--tun-start N] [--tun-end N] [--mtu N] [--net-a A] [--net-b B] [-- комментарий)]`, `server list`, `server use NAME` — атомарно ставит профиль активным и переподнимает туннель, если он работает, `server del NAME` — активный удалить нельзя); активный профиль живёт в привычном `~/sshtun/server.conf` (обратная совместимость со службой и env-логикой), маркер `# sshtun-profile:`; `--net-a/--net-b` должны совпадать с серверной адресацией (второй сервер — в своём /16, например 10.251/16, чтобы не пересекаться с первым); env `SERVER_HOST` по-прежнему имеет самый высокий приоритет и об этом предупреждает; одновременная работа с несколькими серверами не поддерживается;
- файлы-токены `excludes-as.txt` / `excludes-country.txt` — это и есть «список AS/стран»: дописывай токены (`AS9009`, `ru`) напрямую в файл или командами fetch — развёртывание в префиксы происходит при `refresh` и (с TTL 12 ч) при `up`; пользовательские комментарии в этих файлах сохраняются;
- изменения применяются сразу, без перезапуска, если туннель поднят; массовые изменения (тысячи префиксов) идут одним netlink-батчем `ip -batch` (5000 маршрутов — ~0.2 с);
- приоритет маршрутов: ядро выбирает самый длинный префикс (LPM); на равных префиксах include побеждает exclude.

После установки (`install_client.sh`) обёртка доступна как команда `sshtun`:

```bash
sshtun up
sshtun exclude add 203.0.113.0/24
sshtun fetch-as AS9009
sshtun fetch-country ru
sshtun include add 198.51.100.7
sshtun list
```

### `sshtun_pool_windows_client/`

Windows-клиент на Go. Использует Wintun и совместимую с Linux-клиентом CLI-схему. Основной бинарь: `sshtun_pool_client.exe`.

Поддерживает:

- background worker после `start`;
- состояние в `C:\ProgramData\sshtun_pool_client\state.json`;
- runtime-лог в `C:\ProgramData\sshtun_pool_client\sshtun.log`;
- full-tunnel и split-tunnel;
- include/exclude CIDR и route-файлы;
- encrypted private keys;
- `status`, `doctor`, `cleanup`;
- pinning SSH host key через `--host-key-sha256`.

## Требования

### Сервер

Поддерживаемые системы: Linux с systemd, OpenSSH server, iproute2, iptables.

Нужны:

- root-доступ;
- `/dev/net/tun`;
- доступный TCP-порт, по умолчанию `65523`;
- разрешённый forwarding/NAT;
- внешний IPv4-адрес или домен.

### Linux-клиент

Нужны:

- root-доступ для создания TUN и маршрутов;
- `ssh`;
- `iproute2`;
- `flock`;
- `getent`;
- желательно `resolvectl` для DNS.

### macOS-клиент

Нужны:

- macOS Sonoma/Sequoia (Intel и Apple Silicon);
- **bash >= 4.3** (системный bash 3.2 не подходит) — ставится без brew
  через `bash prepare_macos.sh` (нужен Xcode CLT);
- data-plane-бинарь идёт в репозитории (обе архитектуры).

Подробности: [`docs/HOWTO-macos.md`](docs/HOWTO-macos.md).

### Windows-клиент

Нужны:

- Windows с правами администратора;
- `sshtun_pool_client.exe`;
- `wintun.dll` рядом с exe;
- приватный SSH-ключ пользователя.

Для сборки Windows-клиента нужен Go `1.22+` и PowerShell.

## Быстрый старт

### 1. Установка сервера

На сервере:

```bash
sudo bash install_server.sh
```

По умолчанию будут использованы параметры:

```text
user:        sshvpn
port:        65523
tun pool:    tun200..tun250
network:     10.250.0.0/16
mtu:         1400
base dir:    /opt/sshtun_pool
```

Проверка сервисов:

```bash
systemctl status sshtun-pool-sshd.service --no-pager
systemctl status sshtun-pool-network.service --no-pager
```

Проверка listening port:

```bash
ss -lntp | grep 65523
```

Проверка TUN-пула:

```bash
ip addr show tun200
ip addr show tun101
```

### 2. Генерация пользовательского ключа

На админской машине или на клиенте:

```bash
ssh-keygen -t ed25519 -f ./id_ed25519 -N "" -C "user-device"
```

На сервер нужно добавить публичный ключ в:

```text
/opt/sshtun_pool/authorized_keys
```

Рекомендуемая строка ключа:

```text
no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-user-rc ssh-ed25519 AAAAC3... user-device
```

Для random pool mode не добавляйте `tunnel="N"` в `authorized_keys`. Иначе ключ будет прибит к конкретному TUN-номеру и несколько устройств с одним ключом начнут конфликтовать.

После изменения ключей перезапуск сервиса обычно не нужен, но права должны быть корректными:

```bash
chown root:sshvpn /opt/sshtun_pool/authorized_keys
chmod 640 /opt/sshtun_pool/authorized_keys
```

### 3. Подключение с Linux

Full-tunnel режим:

```bash
sudo bash sshtun_pool_client.sh start --host SERVER_IP --key ./id_ed25519
```

Full-tunnel, но локальные/private сети идут напрямую:

```bash
sudo bash sshtun_pool_client.sh start \
  --host SERVER_IP \
  --key ./id_ed25519 \
  --exclude 10.0.0.0/8 \
  --exclude 172.16.0.0/12 \
  --exclude 192.168.0.0/16
```

Split-tunnel режим:

```bash
sudo bash sshtun_pool_client.sh start \
  --host SERVER_IP \
  --key ./id_ed25519 \
  --no-full-tunnel \
  --route 10.10.0.0/16 \
  --route 172.20.0.0/16
```

Маршруты из файла:

```bash
sudo bash sshtun_pool_client.sh start \
  --host SERVER_IP \
  --key ./id_ed25519 \
  --exclude-file ./ru-cidrs.txt
```

Остановка:

```bash
sudo bash sshtun_pool_client.sh stop
```

Диагностика:

```bash
sudo bash sshtun_pool_client.sh status
sudo bash sshtun_pool_client.sh doctor
sudo bash sshtun_pool_client.sh cleanup
```

### 3а. Подключение с macOS

```bash
bash prepare_macos.sh && sudo bash install_macos.sh install
ssh-keygen -t ed25519 -f ~/.ssh/sshtun_ed25519 -N "" -C "$(whoami)-$(hostname)"
# публичный ключ -> /opt/sshtun_pool/authorized_keys на сервере
sshtun server add fin SERVER_IP -- "основной"
sshtun up
sudo /opt/sshtun_client/sshtun-root service-start   # досмотр launchd
```

Полный мануал (тесты политики, служба, сон ноутбука, диагностика):
[`docs/HOWTO-macos.md`](docs/HOWTO-macos.md).

### 4. Сборка Windows-клиента

В каталоге `sshtun_pool_windows_client`:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build.ps1
```

Скрипт скачает `wintun.dll`, подтянет Go-модули и соберёт:

```text
dist\sshtun_pool_client.exe
dist\wintun.dll
```

Сборка под другую архитектуру:

```powershell
.\build.ps1 -Arch amd64
.\build.ps1 -Arch arm64
.\build.ps1 -Arch 386
```

### 5. Подключение с Windows

PowerShell нужно запустить от имени администратора.

Full-tunnel режим:

```powershell
.\dist\sshtun_pool_client.exe start --host SERVER_IP --key .\id_ed25519
```

Full-tunnel с исключением private-сетей:

```powershell
.\dist\sshtun_pool_client.exe start `
  --host SERVER_IP `
  --key .\id_ed25519 `
  --exclude-private
```

Split-tunnel режим:

```powershell
.\dist\sshtun_pool_client.exe start `
  --host SERVER_IP `
  --key .\id_ed25519 `
  --no-full-tunnel `
  --route 10.10.0.0/16 `
  --route 172.20.0.0/16
```

Маршруты из файла:

```powershell
.\dist\sshtun_pool_client.exe start --host SERVER_IP --key .\id_ed25519 --exclude-file .\ru-cidrs.txt
```

Остановка и диагностика:

```powershell
.\dist\sshtun_pool_client.exe status
.\dist\sshtun_pool_client.exe doctor
.\dist\sshtun_pool_client.exe stop
.\dist\sshtun_pool_client.exe cleanup
```

## Основные режимы маршрутизации

### Full tunnel

Весь IPv4-трафик уходит через туннель. Для этого клиент добавляет два маршрута:

```text
0.0.0.0/1
128.0.0.0/1
```

Такой подход не ломает исходный default route полностью и позволяет оставить отдельный bypass-route до реального IP сервера.

### Full tunnel + excludes

Основной интернет идёт через туннель, но отдельные сети уходят напрямую через исходный default gateway.

Типовой пример:

```bash
--exclude 10.0.0.0/8 --exclude 172.16.0.0/12 --exclude 192.168.0.0/16
```

На Windows есть сокращение:

```powershell
--exclude-private
```

### Split tunnel

Через туннель идут только явно указанные сети:

```bash
--no-full-tunnel --route 10.10.0.0/16 --route 172.20.0.0/16
```

Это удобно для корпоративных сетей, внутренних ресурсов или отдельных подсетей.

## CLI-опции

Общие опции Linux/Windows:

```text
--host HOST
--key FILE
--user USER
--port PORT
--tun N
--tun-start N
--tun-end N
--mtu N
--no-full-tunnel
--route CIDR
--route-file FILE
--include CIDR
--include-file FILE
--exclude CIDR
--exclude-file FILE
--route-private
--exclude-private
--no-dns
--dns "1.1.1.1 8.8.8.8"
--no-block-ipv6
--no-clean-orphans
--ask-passphrase
```

Linux-дополнительно:

```text
--remote-setup
--no-remote-setup
--remote-wan-dev DEV
```

Windows-дополнительно:

```text
--adapter-name "SSHTUN Pool"
--host-key-sha256 SHA256:...
--route-style gateway|onlink
--connect-timeout SECONDS
--keepalive-seconds SECONDS
--keepalive-misses N
```

## Безопасная модель MVP

Серверный установщик создаёт отдельный `sshd`-инстанс, отдельного пользователя и отдельный `authorized_keys`:

```text
/opt/sshtun_pool/sshd_config
/opt/sshtun_pool/authorized_keys
/opt/sshtun_pool/ssh_host_ed25519_key
```

Основные ограничения в SSHD-конфигурации:

```text
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
AllowUsers sshvpn
PermitTunnel point-to-point
AllowTcpForwarding no
GatewayPorts no
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitUserEnvironment no
ForceCommand /bin/false
```

Пользователь `sshvpn` создаётся с `nologin`, то есть обычный shell ему не нужен. Для `ssh -w` достаточно TUN-запроса, shell-доступ пользователю не выдаётся.

## Модель пользователей и ключей

Для MVP используется простая модель:

```text
один пользователь = один SSH-ключ
```

Один ключ может использоваться на нескольких устройствах. Так как клиент выбирает случайный `tunN` из пула, несколько устройств с одним ключом не должны конфликтовать, пока есть свободные TUN-номера.

Для production желательно добавить отдельный слой учёта и ограничений:

- лимит одновременных подключений на ключ;
- отзыв ключа через удаление из `authorized_keys`;
- перевыпуск ключа через удаление старого и добавление нового;
- аудит подключений по SSHD-логам;
- версионирование и checksum файла `authorized_keys` при массовой синхронизации.

## Где лежит состояние и логи

### Linux-клиент

```text
/run/sshtun/state
/run/sshtun/ssh.log
/run/sshtun/ssh.last.log
/run/sshtun/known_hosts
/run/sshtun/lock
```

Команды:

```bash
sudo bash sshtun_pool_client.sh status
sudo bash sshtun_pool_client.sh doctor
```

### macOS-клиент

```text
/var/run/sshtun/state
/var/run/sshtun/ssh.log        # live-лог data-plane
/var/log/sshtun.log            # лог службы launchd
```

Команды:

```bash
sshtun status                  # state, pf, utun, DNS
sudo /opt/sshtun_client/sshtun-root backend-run doctor
sudo /opt/sshtun_client/sshtun-root backend-run pfprobe   # маршруты/pf states/счётчики
```

### Windows-клиент

```text
C:\ProgramData\sshtun_pool_client\state.json
C:\ProgramData\sshtun_pool_client\sshtun.log
```

Команды:

```powershell
.\dist\sshtun_pool_client.exe status
.\dist\sshtun_pool_client.exe doctor
```

### Сервер

```bash
journalctl -u sshtun-pool-sshd.service -n 200 --no-pager
journalctl -u sshtun-pool-network.service -n 200 --no-pager
systemctl status sshtun-pool-sshd.service --no-pager
systemctl status sshtun-pool-network.service --no-pager
```

## Проверка после подключения

Linux:

```bash
ip addr show tun200
ip route
curl -4 ifconfig.me
sudo bash sshtun_pool_client.sh status
```

Windows:

```powershell
.\dist\sshtun_pool_client.exe status
curl.exe -4 ifconfig.me
route print -4
ipconfig /all
```

На сервере:

```bash
ip addr show tun200
iptables -t nat -S | grep 10.250
journalctl -u sshtun-pool-sshd.service -f
```

## Типовые проблемы

### `Permission denied`

Проверить:

- публичный ключ добавлен в `/opt/sshtun_pool/authorized_keys`;
- права на файл `authorized_keys` корректные;
- клиент использует правильный приватный ключ;
- подключение идёт на правильный порт `65523`, а не на основной SSH-порт;
- для ключа с passphrase используется `ssh-agent` или `--ask-passphrase`.

### `Connection refused`

Проверить:

```bash
systemctl status sshtun-pool-sshd.service --no-pager
ss -lntp | grep 65523
iptables -S
```

Также убедиться, что порт открыт в firewall/security group провайдера.

### `Could not request tunnel forwarding` / TUN не появляется

Проверить на сервере:

```bash
ls -l /dev/net/tun
cat /opt/sshtun_pool/sshd_config | grep PermitTunnel
systemctl status sshtun-pool-network.service --no-pager
```

В конфигурации SSHD должно быть:

```text
PermitTunnel point-to-point
```

На **macOS** «Tunnel device open failed» — ожидаемое поведение для любого
ssh (Apple и portable не умеют utun): используется собственный data-plane
`sshtun-macos-tun` из репозитория; если он не найден — установщик
сообщит об этом, см. [`docs/HOWTO-macos.md`](docs/HOWTO-macos.md).

### Подключение есть, но интернет не работает

Проверить серверный NAT и forwarding:

```bash
sysctl net.ipv4.ip_forward
iptables -t nat -S | grep MASQUERADE
iptables -S FORWARD | grep 10.250
ip route
```

Проверить, что WAN-интерфейс определился правильно.

### DNS не работает

Linux-клиент использует `resolvectl`, если он установлен. macOS-клиент —
`scutil` (networksetup отказывает демонам на macOS 15+). Проверить:

```bash
resolvectl status
sudo bash sshtun_pool_client.sh doctor
# macOS:
scutil --dns
sshtun doctor
```

Можно отключить изменение DNS:

```bash
--no-dns
```

Или указать свои DNS:

```bash
--dns "1.1.1.1 8.8.8.8"
```

### IPv6 leak

По умолчанию Linux-клиент добавляет blackhole для IPv6 default route. Отключить это поведение можно так:

```bash
--no-block-ipv6
```

Для production лучше отдельно решить, будет ли IPv6 полностью запрещён или поддержан через отдельную маршрутизацию.

### Остались старые TUN-адаптеры

Linux:

```bash
sudo bash sshtun_pool_client.sh cleanup
```

Windows:

```powershell
.\dist\sshtun_pool_client.exe cleanup
```

Cleanup удаляет только управляемые интерфейсы/адаптеры проекта, а не произвольные сетевые интерфейсы системы.

## Настройка через переменные окружения

Серверный установщик поддерживает переопределение параметров через env:

```bash
LISTEN_PORT=65523 \
TUN_NUM_START=200 \
TUN_POOL_SIZE=101 \
TUN_MTU=1400 \
BASE_DIR=/opt/sshtun_pool \
sudo -E bash install_server.sh
```

Основные переменные:

```text
BASE_DIR
SERVICE_NAME
NETWORK_SERVICE_NAME
SYSTEM_USER
LISTEN_PORT
TUN_NUM_START
TUN_POOL_SIZE
TUN_PREFIX
TUN_MTU
TUN_NET_A
TUN_NET_B
TUN_POOL_CIDR
LIMIT_NOFILE
TASKS_MAX
```

Linux-клиент также можно настраивать через env, но обычно удобнее использовать CLI-флаги.

## Что важно для MVP

Минимальный рабочий набор:

```text
install_server.sh
sshtun_pool_client.sh
sshtun_full.sh
install_client.sh
sshtun_macos.sh
install_macos.sh
sshtun_root.sh
prepare_macos.sh
sshtun_macos_client/**
sshtun_pool_windows_client/build.ps1
sshtun_pool_windows_client/go.mod
sshtun_pool_windows_client/go.sum
sshtun_pool_windows_client/cmd/sshtun_pool_client/main.go
sshtun_pool_windows_client/internal/**
```

Для сборки Windows-клиента нужны все Go-файлы внутри `cmd/` и `internal/`, а также `go.mod`, `go.sum`, `build.ps1`. Удалять `*_other.go` не стоит: они нужны для корректной кроссплатформенной сборки и заглушек под неподдерживаемые платформы.

## Ограничения текущей версии

- Это MVP/прототип транспортного слоя, а не полный коммерческий клиент с GUI, автообновлением и подписанным installer.
- Нет центрального control-plane для выдачи/отзыва ключей.
- Нет встроенного лимита одновременных подключений на один ключ.
- Нет встроенной синхронизации `authorized_keys` по флоту серверов.
- Нет встроенного мониторинга качества канала.
- IPv6 по умолчанию скорее блокируется, чем полноценно туннелируется.
- Windows-сборка требует Wintun DLL рядом с exe.

## Рекомендованный roadmap после MVP

1. Добавить генерацию пользовательского JSON-профиля: host, port, user, private key, routing mode, DNS, route/exclude files.
2. Добавить централизованный revoke/reissue ключей.
3. Добавить лимит одновременных подключений на ключ.
4. Добавить безопасную синхронизацию `authorized_keys` по серверам.
5. Добавить checksum/version для файлов ключей.
6. Добавить GUI/Tray-клиент поверх CLI-ядра.
7. Подписать Windows/macOS binaries и installer.
8. Добавить автообновление клиента.
9. Вынести большие списки маршрутов, например country CIDR, в отдельный обновляемый файл/сервис. — сделано: `sshtun fetch-as` / `fetch-country` / `refresh` (2026-11-01)
10. Добавить полноценный healthcheck: SSH connect, tunnel up, DNS, public IP, route test, packet pump stats.
11. GUI-оболочка для Linux и macOS поверх CLI-ядра: старт/стоп туннеля, статус, просмотр логов и конфигов, вызов редактора.

## Короткая шпаргалка

Сервер:

```bash
sudo bash install_server.sh
systemctl status sshtun-pool-sshd.service --no-pager
```

Ключ:

```bash
ssh-keygen -t ed25519 -f ./id_ed25519 -N "" -C "user-device"
cat ./id_ed25519.pub >> /opt/sshtun_pool/authorized_keys
```

Linux connect:

```bash
sudo bash sshtun_pool_client.sh start --host SERVER_IP --key ./id_ed25519
sudo bash sshtun_pool_client.sh stop
```

macOS connect:

```bash
sshtun up
sudo /opt/sshtun_client/sshtun-root service-start   # досмотр launchd
sshtun down
```

Windows build:

```powershell
cd sshtun_pool_windows_client
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build.ps1
```

Windows connect:

```powershell
.\dist\sshtun_pool_client.exe start --host SERVER_IP --key .\id_ed25519
.\dist\sshtun_pool_client.exe stop
```
