#!/usr/bin/env bash
# shellcheck disable=SC2034
set -Eeuo pipefail
IFS=$'\n\t'

# ==========================================================
# sshtun_macos.sh — macOS-бэкенд для обёртки sshtun_full.sh
#
# Реализует ТОТ ЖЕ контракт, что и sshtun_pool_client.sh (Linux):
#   start --host H --key K [--port N] [--user U] [--tun-start S] [--tun-end E]
#         [--mtu N] [--exclude-file F]... [--route-file F]... [--foreground]
#   stop | status | doctor | cleanup
#   apply-diff            (stdin: строки "add CIDR" / "del CIDR"; пересборка
#                          pf-таблиц «на живую», без перезапуска туннеля)
#
# Отличия от Linux-реализации (механика, семантика та же):
#   - utun вместо tun (устройство находится по diff ifconfig -l; номер,
#     запрошенный у сервера -w N:N, совпадает с пулом сервера)
#   - маршрутная политика — pfctl: exclude/include-префиксы живут в таблицах
#     pf, catch-all идёт route-to в utun. Быстро: 12k+ префиксов загружаются
#     pfctl'ом за секунды, а не route add по одному
#   - семантика префиксов: pf ищет самый длинный префикс в таблице (LPM);
#     на равных длинах первое quick-правило (includes) побеждает
#   - DNS через networksetup (per-service), restore при stop
#   - блок IPv6: pf block inet6 (вместо blackhole-маршрутов)
#   - lock через mkdir (flock отсутствует на macOS)
#   - state: /var/run/sshtun (macOS аналог /run/sshtun)
#
# Требования: bash >= 4.3 (brew install bash — системный bash 3.2 macOS
# не поддерживает nameref/associative arrays, которые использует обёртка),
# python3 (для RIPEstat в обёртке, предустановлен с CLT), pfctl/networksetup
# — из коробки.
# ==========================================================

SSH_USER="${SSH_USER:-sshvpn}"
SSH_PORT="${SSH_PORT:-65523}"
# Диапазон 200..250 — осознанный компромисс: 0..~15 занимает система macOS,
# 100..199 может занимать NetworkManager на Linux-хостах, macOS не умеет
# utun > 255 («Tunnel device open failed»).
TUN_START="${TUN_START:-200}"
TUN_END="${TUN_END:-250}"
TUN_MTU="${TUN_MTU:-1400}"

TUN_NET_A="${TUN_NET_A:-10}"
TUN_NET_B="${TUN_NET_B:-250}"

# SSH-бинарник: Apple ssh НЕ умеет -w/utun («Tunnel device open failed») —
# нужен portable OpenSSH (brew или сборка prepare_macos.sh). Путь к нему
# установщик пишет в env.conf рядом со скриптом (конфиг source'ится и
# напрямую, и через root-хелпер, где $HOME указывает в /var/root).
SCRIPT_DIR_MACOS="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR_MACOS/env.conf" ]] && source "$SCRIPT_DIR_MACOS/env.conf"
SSH_BIN="${SSH_BIN:-ssh}"

STATE_DIR="${STATE_DIR:-/var/run/sshtun}"
STATE_FILE="$STATE_DIR/state"
SSH_LOG="$STATE_DIR/ssh.log"
SSH_LAST_LOG="$STATE_DIR/ssh.last.log"
KNOWN_HOSTS_FILE="$STATE_DIR/known_hosts"
LOCK_DIR="$STATE_DIR/lock.d"

FULL_TUNNEL="${FULL_TUNNEL:-1}"
SET_DNS="${SET_DNS:-1}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1 8.8.8.8}"
BLOCK_IPV6="${BLOCK_IPV6:-1}"
SSH_BATCH_MODE="${SSH_BATCH_MODE:-yes}"
FOREGROUND="${FOREGROUND:-0}"

# pf: anchor и таблицы. Статичный каркас anchor'а ставит install_macos.sh
# в /etc/pf.anchors/com.sshtun (+ строка anchor "com.sshtun" в /etc/pf.conf);
# runtime-содержимое (таблицы + правила с подставленным utun) генерим сюда.
PF_ANCHOR_NAME="com.sshtun"
PF_ANCHOR_FRAME="/etc/pf.anchors/com.sshtun"
PF_RUNTIME_DIR="$STATE_DIR/pf"
ANCHOR_CONF="$PF_RUNTIME_DIR/anchor.conf"
TBL_EXCLUDES="$PF_RUNTIME_DIR/excludes.table"
TBL_INCLUDES="$PF_RUNTIME_DIR/includes.table"
TBL_BYPASS="$PF_RUNTIME_DIR/bypass.table"

HOST=""
KEY_FILE=""
SERVER_REAL_IP=""
DEFAULT_DEV=""
DEFAULT_GW=""
SSH_PID=""
TUN_NUM=""
TUN_DEV=""
SERVER_TUN_IP=""
CLIENT_TUN_IP=""
START_OK="0"
HAD_PF_DISABLED="0"   # мы сами включили pf — на stop выключим
DNS_SERVICE=""
DNS_SAVED=0

EXCLUDE_FILES=()
ROUTE_FILES=()

log(){ echo "[$(date '+%Y-%m-%dT%H:%M:%S%z' | sed -E 's/([0-9]{2})$/:\1/')] $*" 2>/dev/null || true; }
die(){ echo "[ERROR] $*" >&2 || true; exit 1; }

usage() {
  cat <<EOFUSAGE
Usage:
  sudo $0 start --host SERVER --key /path/id_ed25519 [options]
  sudo $0 stop | status | doctor | cleanup
  sudo $0 apply-diff      (stdin: "add CIDR"/"del CIDR"; live-пересборка таблиц)

Start options:
  --host H            server address (env SERVER_HOST)
  --port N            default $SSH_PORT
  --user U            default $SSH_USER
  --key FILE          private key path (required)
  --tun-start N       requested server-side tun number range start ($TUN_START)
  --tun-end N         range end ($TUN_END)
  --mtu N             tun MTU ($TUN_MTU)
  --exclude-file F    CIDR list routed DIRECTLY (may repeat)
  --route-file F      CIDR list forced via tunnel (may repeat)
  --foreground        stay in foreground supervising ssh (launchd mode)

Env: STATE_DIR TUN_NET_A TUN_NET_B DNS_SERVERS SET_DNS BLOCK_IPV6
EOFUSAGE
}

need_root() { [[ "$(id -u)" == "0" ]] || die "Запускать от root (обёртка делает sudo сама)"; }

# --- lock через mkdir: атомарно, без flock --------------------------------
acquire_lock() {
  mkdir -p "$STATE_DIR"
  local i=0
  for ((i=0; i<50; i++)); do
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      printf '%s\n' "$$" > "$LOCK_DIR/pid"
      return 0
    fi
    # stale lock: держатель мёртв — подчищаем
    local holder=""
    holder="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    if [[ -n "$holder" && "$holder" =~ ^[0-9]+$ ]] && ! kill -0 "$holder" 2>/dev/null; then
      rm -rf "$LOCK_DIR"
      continue
    fi
    sleep 0.2
  done
  die "Another sshtun operation is running (lock: $LOCK_DIR)"
}
release_lock() { rm -rf "$LOCK_DIR" 2>/dev/null || true; }

# --- утилиты ---------------------------------------------------------------
# Отсортированные уникальные CIDR-строки из файлов (комментарии/пустые — мимо).
read_cidrs() { # files...
  local f=""
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" \
      | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$' || true
  done | sort -u
}

utun_list() { ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun' | sort || true; }

detect_default_route() {
  local out=""
  out="$(route -n get default 2>/dev/null || true)"
  DEFAULT_GW="$(awk '/^ *gateway:/{print $2; exit}' <<<"$out")"
  DEFAULT_DEV="$(awk '/^ *interface:/{print $2; exit}' <<<"$out")"
  [[ -n "$DEFAULT_DEV" ]] || die "Не найден default route"
}

resolve_server_ipv4() {
  local ips=""
  ips="$(dig +short A "$HOST" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
  [[ -n "$ips" ]] || die "Не резолвится $HOST (dig +short A пусто)"
  SERVER_REAL_IP="$(head -n1 <<<"$ips")"
}

calc_pair_ips() { # tun_num
  local offset=$(($1 - TUN_START))
  (( offset >= 0 )) || die "tun number $1 ниже TUN_START $TUN_START"
  local base=$((offset * 4))
  local oct3=$((base / 256))
  local oct4=$((base % 256))
  (( oct3 <= 255 && oct4 <= 253 )) || die "tun pool велик для ${TUN_NET_A}.${TUN_NET_B}.0.0/16"
  SERVER_TUN_IP="${TUN_NET_A}.${TUN_NET_B}.${oct3}.$((oct4 + 1))"
  CLIENT_TUN_IP="${TUN_NET_A}.${TUN_NET_B}.${oct3}.$((oct4 + 2))"
}

# --- pf: таблицы и правила --------------------------------------------------
pf_write_tables() { # генерирует файлы таблиц из EXCLUDE_FILES/ROUTE_FILES + bypass
  mkdir -p "$PF_RUNTIME_DIR"
  read_cidrs "${EXCLUDE_FILES[@]}" > "$TBL_EXCLUDES"
  read_cidrs "${ROUTE_FILES[@]}" > "$TBL_INCLUDES"
  {
    printf '%s/32\n' "$SERVER_REAL_IP"
    printf '%s/32\n' "$DEFAULT_GW"
    printf '%s\n' "169.254.0.0/16"
  } | sort -u > "$TBL_BYPASS"
}

pf_write_anchor() { # правила с подставленным utun/peer
  {
    printf '# generated by sshtun_macos.sh — не править\n'
    printf 'table <sshtun_excludes> persist file "%s"\n' "$TBL_EXCLUDES"
    printf 'table <sshtun_includes> persist file "%s"\n' "$TBL_INCLUDES"
    printf 'table <sshtun_bypass> persist file "%s"\n' "$TBL_BYPASS"
    # порядок = семантика: include ВСЕГДА побеждает exclude (pf не делает
    # LPM между таблицами — первое quick-правило; на Linux более длинный
    # exclude-префикс выиграл бы), exclude, bypass (сервер/шлюз/link-local),
    # multicast, IPv6-block, catch-all.
    # ИСКЛЮЧЕНИЯ — НЕ pf, а МАРШРУТЫ (apply_exclude_routes): из-за /1-халв
    # сокеты выбирают src = адрес utun, и ни route-to, ни binat ответы
    # сокетам не вернут (state binat прибит интерфейсом utun, а ответы
    # приходят на en0). Реальные маршруты через шлюз чинят src-selection
    # в корне: сокет сразу биндится физическим адресом, ответы возвращаются
    # естественно — как на Linux. Правило ниже — plain pass: матчит пакеты
    # до catch-all (счётчики pfctl -vvsr) и документирует набор.
    printf 'pass out quick route-to (%s %s) inet from any to <sshtun_includes>\n' "$TUN_DEV" "$SERVER_TUN_IP"
    printf 'pass out quick inet from any to <sshtun_excludes>\n'
    printf 'pass out quick inet from any to <sshtun_bypass>\n'
    printf 'pass out quick inet from any to 224.0.0.0/4\n'
    if [[ "$BLOCK_IPV6" == "1" ]]; then
      printf 'block drop out quick inet6 all\n'
    fi
    printf 'pass out quick inet all\n'
    # ВХОД: pf включается ПОСЛЕ установки SSH-соединения — у него нет state,
    # и inbound-сегменты (keepalive/data от сервера) дропались бы дефолтной
    # политикой (наблюдено: «Timeout, client not responding» через ~90 с,
    # туннель умирал). Пускаем inbound от сервера/шлюза (bypass), из LAN,
    # link-local/mcast и DHCP-replies; ответы на наши исходящие и так
    # проходят по state (keep state у pass out).
    printf 'pass in quick inet from <sshtun_bypass> to any\n'
    printf 'pass in quick inet from { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 } to any\n'
    printf 'pass in quick proto udp from port 67 to port 68\n'
  } > "$ANCHOR_CONF"
}

pf_enabled() { pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || pfctl -s info 2>/dev/null | grep -q '^Enabled'; }

pf_ensure_enabled() {
  if ! pfctl -s info >/dev/null 2>&1 || ! pf_enabled; then
    pfctl -e >/dev/null 2>&1 || die "pfctl -e не удался (anchor в /etc/pf.conf есть?)"
    HAD_PF_DISABLED="1"
    log "pf включён нами (ранее был выключен)"
  fi
}

pf_load_anchor() {
  [[ -f "$PF_ANCHOR_FRAME" ]] || die "Нет $PF_ANCHOR_FILE — запустите install_macos.sh"
  # anchor должен существовать в main ruleset: если pf.conf поправили при
  # установке, а main ruleset ещё не перечитывали — перечитываем целиком.
  if ! pfctl -s anchors 2>/dev/null | grep -qx "$PF_ANCHOR_NAME"; then
    pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
  fi
  # таблицы должны существовать до загрузки правил
  : > "$TBL_EXCLUDES" 2>/dev/null || true
  pf_write_tables
  pf_write_anchor
  pf_ensure_enabled
  local pf_err=""
  pf_err="$(pfctl -a "$PF_ANCHOR_NAME" -f "$ANCHOR_CONF" 2>&1)" \
    || die "pfctl не загрузил anchor: $pf_err
anchors в ruleset: $(pfctl -s anchors 2>/dev/null | tr '\n' ' ')
anchor-строка в pf.conf: $(grep -n 'anchor "com.sshtun"' /etc/pf.conf 2>/dev/null || echo 'ОТСУТСТВУЕТ')"
  # КЛЮЧЕВОЕ: «persist file» читает файл ТОЛЬКО при создании таблицы.
  # После stop (pfctl -F all опустошает таблицы) повторный «pfctl -f»
  # правила перечитывает, а таблицы оставляет ПУСТЫМИ — исключения
  # молча перестают работать. Поэтому наполняем их явно при каждой
  # загрузке anchor.
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_excludes -T replace -f "$TBL_EXCLUDES" 2>/dev/null || true
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_includes -T replace -f "$TBL_INCLUDES" 2>/dev/null || true
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_bypass   -T replace -f "$TBL_BYPASS"   2>/dev/null || true
}

pf_flush_anchor() {
  pfctl -a "$PF_ANCHOR_NAME" -F all >/dev/null 2>&1 || true
  if [[ "$HAD_PF_DISABLED" == "1" ]]; then
    pfctl -d >/dev/null 2>&1 || true
  fi
}

# Два полу-default'а через peer utun: catch-all маршрутизация в туннель без
# pf route-to (чтобы src выбирался ядром адресом utun). Применяется ПОСЛЕ
# ifconfig; снимается при stop. ВНИМАНИЕ: macOS route(8) не ест CIDR-форму
# «-net 0.0.0.0/1» — только классика «-netmask 128.0.0.0».
add_tunnel_routes() {
  local rc=0
  route -q add -net 0.0.0.0 -netmask 128.0.0.0 "$SERVER_TUN_IP" >/dev/null 2>&1 || rc=1
  route -q add -net 128.0.0.0 -netmask 128.0.0.0 "$SERVER_TUN_IP" >/dev/null 2>&1 || rc=1
  (( rc == 0 )) || log "WARNING: полу-default маршруты не добавились (route add rc=$rc)"
}

del_tunnel_routes() {
  route -q delete -net 0.0.0.0 -netmask 128.0.0.0 "$SERVER_TUN_IP" >/dev/null 2>&1 || true
  route -q delete -net 128.0.0.0 -netmask 128.0.0.0 "$SERVER_TUN_IP" >/dev/null 2>&1 || true
}

# Хост-маршрут до СЕРВЕРА через дефолтный шлюз. КРИТИЧНО: полу-default'ы
# (/1 в utun) иначе перехватывают и сам ssh-поток — кэш маршрута у сокета
# живёт недолго, и через ~30 с внешнее ssh-соединение начинает ходить в utun
# (пакеты возвращаются data-plane'у внутрь процесса и глохнут: сервер шлёт
# keepalive и не получает ACK, «Timeout, client not responding» ~T+90).
# Паритет с Linux-клиентом: там add_server_bypass_route есть с самого начала.
add_server_bypass_route() {
  route -q add -host "$SERVER_REAL_IP" "$DEFAULT_GW" >/dev/null 2>&1 \
    || log "WARNING: bypass-маршрут до сервера не добавлен (route add rc=$?)"
}

del_server_bypass_route() {
  route -q delete -host "$SERVER_REAL_IP" "$DEFAULT_GW" >/dev/null 2>&1 || true
}

# Исключения реализованы МАРШРУТАМИ, а не pf: из-за /1-халв сокеты выбирают
# src = адрес utun, и pf-уровень (route-to/binat) не способен вернуть ответы
# таким сокетам (state binat прибит интерфейсом utun, ответы идут на en0).
# Реальные маршруты через шлюз чинят src-selection в корне. Порядок ~3 мс на
# префикс (~40 с на 12,5k) — поэтому ставим/снимаем в ФОНЕ, ход в лог.
apply_exclude_routes() { # op(add|delete) cidr-file [gw]
  local op="$1" f="$2" gw="${3:-}"
  [[ -s "$f" ]] || return 0
  [[ -n "$gw" ]] || gw="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')"
  [[ -n "$gw" ]] || { log "WARNING: шлюз не определён — exclude-маршруты ($op) пропущены"; return 0; }
  python3 - "$op" "$gw" "$f" >>"$STATE_DIR/routes.log" 2>&1 <<'PY' || log "WARNING: exclude-маршруты ($op) применены частично (routes.log)"
import sys, ipaddress, subprocess
op, gw, path = sys.argv[1], sys.argv[2], sys.argv[3]
ok = bad = 0
with open(path) as fh:
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            bad += 1
            continue
        if net.version != 4:
            continue
        subprocess.run(["route", "-q", op, "-net", str(net.network_address),
                        "-netmask", str(net.netmask), gw], capture_output=True)
        ok += 1
print(f"exclude-routes {op}: {ok} ok, {bad} bad", file=sys.stderr)
PY
}

# Живое применение diff'ов от обёртки: пересобираем таблицы из файлов
# политики (обёртка уже перезаписала exclude/include-файлы) и перегружаем
# anchor. Перечитываем списки из state (пути файлов политики).
apply_diff() {
  need_root
  [[ -f "$STATE_FILE" ]] || die "Нет state — туннель не работает?"
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  EXCLUDE_FILES=()
  ROUTE_FILES=()
  local f=""
  for f in ${EXCLUDE_FILES_SAVED:-}; do EXCLUDE_FILES+=("$f"); done
  for f in ${ROUTE_FILES_SAVED:-}; do ROUTE_FILES+=("$f"); done
  [[ -n "${TUN_DEV:-}" && -n "${SERVER_TUN_IP:-}" ]] || die "state неполон (TUN_DEV/SERVER_TUN_IP)"
  mkdir -p "$PF_RUNTIME_DIR"
  # дельта exclude-маршрутов: сохраняем прошлый набор ДО перезаписи таблиц
  local prev="$PF_RUNTIME_DIR/excludes.prev"
  [[ -f "$TBL_EXCLUDES" ]] && cp "$TBL_EXCLUDES" "$prev" || : > "$prev"
  pf_write_tables
  pf_write_anchor
  pfctl -a "$PF_ANCHOR_NAME" -f "$ANCHOR_CONF" >/dev/null \
    || die "pfctl reload anchor не удался"
  # см. pf_load_anchor: «persist file» не перечитывает файл при reload —
  # наполняем таблицы явно.
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_excludes -T replace -f "$TBL_EXCLUDES" 2>/dev/null || true
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_includes -T replace -f "$TBL_INCLUDES" 2>/dev/null || true
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_bypass   -T replace -f "$TBL_BYPASS"   2>/dev/null || true
  # маршруты: только разница против прошлого набора (дешёво даже на 12,5k)
  local add_f="$PF_RUNTIME_DIR/excludes.add" del_f="$PF_RUNTIME_DIR/excludes.del"
  comm -13 <(sort -u "$prev") <(sort -u "$TBL_EXCLUDES") > "$add_f"
  comm -23 <(sort -u "$prev") <(sort -u "$TBL_EXCLUDES") > "$del_f"
  apply_exclude_routes add "$add_f"
  apply_exclude_routes delete "$del_f"
  rm -f "$add_f" "$del_f"
  log "pf-таблицы пересобраны: excludes=$(grep -c . "$TBL_EXCLUDES" || true) includes=$(grep -c . "$TBL_INCLUDES" || true)"
}

# --- DNS --------------------------------------------------------------------
# networksetup -setdnsservers на macOS 15 ( Sonoma+ тоже) из фоновых/daemon
# процессов отказывает (privacy-ограничения) — работаем через scutil с
# Setup:/Network/Service/<UUID>/DNS (классический API VPN-клиентов).
# UUID основного сервиса берём из State:/Network/Global/IPv4 (PrimaryService).
net_service_for_dev() { # en0 -> "Wi-Fi" (для сообщений)
  networksetup -listnetworkserviceorder 2>/dev/null \
    | awk -v dev="$1" '
        /^\([0-9]+\)/ { svc=$0 }
        $0 ~ "Device: " dev "\\)" {
          sub(/^\([0-9]+\) /, "", svc)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", svc)
          print svc; exit
        }'
}

primary_service_uuid() {
  scutil <<< "show State:/Network/Global/IPv4" 2>/dev/null \
    | awk '/PrimaryService :/{print $3; exit}'
}

dns_current_servers() { # UUID -> "1.1.1.1 8.8.8.8" или пусто
  local uuid="$1" out=""
  out="$(scutil <<< "show Setup:/Network/Service/$uuid/DNS" 2>/dev/null || true)"
  awk '/^[[:space:]]+[0-9]+ : /{printf "%s ", $3} END{printf "\n"}' <<<"$out" \
    | sed -e 's/[[:space:]]*$//'
}

dns_save_and_set() {
  local uuid=""
  uuid="$(primary_service_uuid)"
  [[ -n "$uuid" ]] || { log "WARNING: не нашёл PrimaryService — DNS не трогаю"; return 0; }
  DNS_SERVICE="$(net_service_for_dev "$DEFAULT_DEV")"
  local old_srv=""
  old_srv="$(dns_current_servers "$uuid")"
  {
    printf 'DNS_SERVICE=%q\n' "$DNS_SERVICE"
    printf 'DNS_SERVICE_UUID=%q\n' "$uuid"
    printf 'DNS_OLD_SERVERS=%q\n' "$old_srv"
  } >> "$STATE_FILE"
  # shellcheck disable=SC2086
  scutil >/dev/null 2>&1 <<EOF || { log "WARNING: scutil set DNS не удался"; return 0; }
d.init
d.add ServerAddresses * $DNS_SERVERS
set Setup:/Network/Service/$uuid/DNS
EOF
  DNS_SAVED=1
  log "DNS ${DNS_SERVICE:-$uuid} -> $DNS_SERVERS"
}

dns_restore() {
  # shellcheck disable=SC1090
  source "$STATE_FILE" 2>/dev/null || return 0
  local uuid="${DNS_SERVICE_UUID:-}"
  [[ -n "$uuid" ]] || return 0
  if [[ -z "${DNS_OLD_SERVERS:-}" ]]; then
    scutil >/dev/null 2>&1 <<EOF
remove Setup:/Network/Service/$uuid/DNS
EOF
  else
    # shellcheck disable=SC2086
    scutil >/dev/null 2>&1 <<EOF
d.init
d.add ServerAddresses * ${DNS_OLD_SERVERS}
set Setup:/Network/Service/$uuid/DNS
EOF
  fi
  log "DNS ${DNS_SERVICE:-$uuid} восстановлен"
}

# --- ssh и utun -------------------------------------------------------------
find_new_utun() { # snapshot_file -> new dev name
  local snap="$1" i=0 dev=""
  for ((i=0; i<75; i++)); do
    while IFS= read -r dev; do
      [[ -n "$dev" ]] || continue
      if ! grep -qxF "$dev" "$snap"; then printf '%s' "$dev"; return 0; fi
    done < <(utun_list)
    sleep 0.2
  done
  return 1
}

write_state() {
  : > "$STATE_FILE"
  {
    printf 'SSH_PID=%q\n' "$SSH_PID"
    printf 'HOST=%q\n' "$HOST"
    printf 'SERVER_REAL_IP=%q\n' "$SERVER_REAL_IP"
    printf 'SSH_USER=%q\n' "$SSH_USER"
    printf 'SSH_PORT=%q\n' "$SSH_PORT"
    printf 'TUN_NUM=%q\n' "$TUN_NUM"
    printf 'TUN_DEV=%q\n' "$TUN_DEV"
    printf 'SERVER_TUN_IP=%q\n' "$SERVER_TUN_IP"
    printf 'CLIENT_TUN_IP=%q\n' "$CLIENT_TUN_IP"
    printf 'FULL_TUNNEL=%q\n' "$FULL_TUNNEL"
    printf 'SET_DNS=%q\n' "$SET_DNS"
    printf 'BLOCK_IPV6=%q\n' "$BLOCK_IPV6"
    printf 'SSH_BATCH_MODE=%q\n' "$SSH_BATCH_MODE"
    printf 'SUPERVISED=%q\n' "$([[ "$FOREGROUND" == "1" ]] && printf 1 || printf 0)"
    printf 'TUN_NET_A=%q\n' "$TUN_NET_A"
    printf 'TUN_NET_B=%q\n' "$TUN_NET_B"
    printf 'EXCLUDE_FILES_SAVED=%q\n' "${EXCLUDE_FILES[*]:-}"
    printf 'ROUTE_FILES_SAVED=%q\n' "${ROUTE_FILES[*]:-}"
    printf 'HAD_PF_DISABLED=%q\n' "$HAD_PF_DISABLED"
  } >> "$STATE_FILE"
  chmod 600 "$STATE_FILE" 2>/dev/null || true
}

start_vpn() {
  need_root
  acquire_lock
  START_OK="0"
  # При неудачном старте маркер «starting» из state надо снять — иначе
  # status будет вечно показывать «starting». Успех: START_OK=1 (ниже).
  trap 'rc=$?; if [[ "$START_OK" != "1" && $rc -ne 0 ]]; then rm -f "$STATE_FILE" 2>/dev/null || true; fi; release_lock' EXIT

  [[ -n "$HOST" ]] || die "--host не задан"
  [[ -f "$KEY_FILE" ]] || die "ключ не найден: $KEY_FILE"

  # Ранний маркер «стартую»: пока идёт подключение, status показывает
  # понятное «starting» вместо загадочного «stopped». Успех — write_state
  # перезапишет маркер полным state; неудача — stop_cleanup сотрёт файл.
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR" 2>/dev/null || true
  printf 'PHASE=starting\nSTARTED_AT=%s\nHOST=%s\nSSH_USER=%s\nSSH_PORT=%s\nSSH_PID=\n' \
    "$(date +%s)" "$HOST" "$SSH_USER" "$SSH_PORT" > "$STATE_FILE"

  log "SSH: $SSH_BIN ($("$SSH_BIN" -V 2>&1 | head -n1 || true))"

  detect_default_route
  log "Default route: via $DEFAULT_GW dev $DEFAULT_DEV"
  resolve_server_ipv4
  log "Server real IP: $SERVER_REAL_IP"

  # случайный номер из диапазона; сервер должен иметь tunN в своём пуле.
  # ВАЖНО (macOS): локальный и удалённый номера -w НЕ обязаны совпадать.
  # Локально берём МАЛЕНЬКИЙ свободный utun (0..~3 занимает система, высокие
  # номера ядро macOS не отдаёт: «Tunnel device open failed»), а серверу
  # просим tunN из пула — адресация считается по НОМЕРУ СЕРВЕРА.
  TUN_NUM=$((RANDOM % (TUN_END - TUN_START + 1) + TUN_START))
  calc_pair_ips "$TUN_NUM"
  log "Trying tun$TUN_NUM: client=$CLIENT_TUN_IP, server=$SERVER_TUN_IP"

  mkdir -p "$STATE_DIR" "$PF_RUNTIME_DIR"
  chmod 700 "$STATE_DIR" 2>/dev/null || true

  # Дата-плейн: Go-бинарь (протокол tun@openssh.com в userspace — замена
  # «ssh -w», которого на macOS нет: ни Apple, ни portable OpenSSH не умеют
  # utun). Поиск: env.conf/переменная → каталог скрипта → ~/sshtun-tools
  # пользователя (sudo сохраняет SUDO_USER; под launchd без SUDO_USER
  # работает env.conf).
  # Архитектура: в репо лежат обе сборки (Intel/Apple Silicon), выбираем
  # под uname -m; имя без суффикса — legacy-единичная сборка (фолбэком).
  if [[ -z "${TUN_GO_BIN:-}" ]]; then
    local _uh="" _c="" _sfx=""
    _uh="$(eval echo "~${SUDO_USER:-$USER}" 2>/dev/null || true)"
    case "$(uname -m 2>/dev/null || echo x86_64)" in
      arm64|aarch64) _sfx="arm64" ;;
      *) _sfx="amd64" ;;
    esac
    # проход 1: бинарь под архитектуру хоста; проход 2: legacy без суффикса
    for _c in \
      "$_uh/sshtun-tools/bin/sshtun-macos-tun.$_sfx" \
      "$SCRIPT_DIR_MACOS/sshtun-macos-tun.$_sfx" \
      "$SCRIPT_DIR_MACOS/sshtun_macos_client/sshtun-macos-tun.$_sfx" \
      "/opt/sshtun_client/sshtun-macos-tun.$_sfx" \
      "$_uh/sshtun-tools/bin/sshtun-macos-tun" \
      "$SCRIPT_DIR_MACOS/sshtun-macos-tun" \
      "$SCRIPT_DIR_MACOS/sshtun_macos_client/sshtun-macos-tun" \
      "/opt/sshtun_client/sshtun-macos-tun"; do
      [[ -x "$_c" ]] || continue
      # Пользовательская сборка в приоритете: обновление бинаря без root.
      TUN_GO_BIN="$_c"
      break
    done
  fi

  if [[ -n "${TUN_GO_BIN:-}" ]]; then
    log "data-plane: $TUN_GO_BIN (tun@openssh.com, userspace)"
    : > "$SSH_LOG"
    "$TUN_GO_BIN" \
        --host "$HOST" --port "$SSH_PORT" --user "$SSH_USER" \
        --key "$KEY_FILE" --remote-unit "$TUN_NUM" --mtu "$TUN_MTU" \
        --known-hosts "$KNOWN_HOSTS_FILE" \
        >"$SSH_LOG" 2>&1 &
    SSH_PID=$!
    printf '%s\n' "$SSH_PID" > "$STATE_DIR/ssh.pid"
    # ждём маркер UTUN_READY (канал открыт); смерть процесса — ранний выход
    TUN_DEV=""
    local i=0
    for ((i=0; i<240; i++)); do
      if ! kill -0 "$SSH_PID" 2>/dev/null; then break; fi
      TUN_DEV="$(sed -n 's/^UTUN_READY dev=\([^[:space:]]*\).*/\1/p' "$SSH_LOG" 2>/dev/null | tail -n1)"
      [[ -n "$TUN_DEV" ]] && break
      sleep 0.25
    done
    if [[ -z "$TUN_DEV" ]]; then
      wait "$SSH_PID" 2>/dev/null || true
      cp "$SSH_LOG" "$SSH_LAST_LOG" 2>/dev/null || true
      die "туннель не поднялся; лог: $(tail -n 8 "$SSH_LOG" 2>/dev/null | tr '\n' ' ')"
    fi
  else
    log "data-plane: $SSH_BIN -w (встроенный ssh; на macOS обычно не работает — соберите sshtun_macos_client)"

  local before_utuns
  before_utuns="$(mktemp)"
  utun_list > "$before_utuns"

  # локальный utun: первый свободный из 4..15
  local local_utun=""
  local n=0
  for n in 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ! grep -qxF "utun$n" "$before_utuns"; then local_utun="$n"; break; fi
  done
  [[ -n "$local_utun" ]] || die "Нет свободного utun (4..15 заняты)"

  # SSH: BatchMode (ключ без passphrase), KeepAlive — как на Linux.
  # RemoteCommand запрещён на сервере, -N — просто держим туннель.
  # -w local:remote — локальный utun4..15 (macOS), удалённый tunN из пула.
  "$SSH_BIN" -i "$KEY_FILE" -p "$SSH_PORT" -l "$SSH_USER" \
      -w "$local_utun:$TUN_NUM" \
      -o Tunnel=point-to-point \
      -o ExitOnForwardFailure=yes \
      -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
      -o TCPKeepAlive=yes \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
      -o StrictHostKeyChecking=accept-new \
      -N "$HOST" >"$SSH_LOG" 2>&1 &
  SSH_PID=$!
  printf '%s\n' "$SSH_PID" > "$STATE_DIR/ssh.pid"

  TUN_DEV="$(find_new_utun "$before_utuns" 2>/dev/null || true)"
  rm -f "$before_utuns"
  if [[ -z "$TUN_DEV" ]]; then
    wait "$SSH_PID" 2>/dev/null || true
    cp "$SSH_LOG" "$SSH_LAST_LOG" 2>/dev/null || true
    die "utun не появился; ssh log: $(tail -n 5 "$SSH_LOG" 2>/dev/null | tr '\n' ' ')"
  fi
  fi

  # адреса point-to-point + mtu
  ifconfig "$TUN_DEV" inet "$CLIENT_TUN_IP" "$SERVER_TUN_IP" mtu "$TUN_MTU" up \
    || die "ifconfig $TUN_DEV не удался"

  # маршрутная политика (pf + полу-default'а в таблице + bypass до сервера)
  pf_load_anchor
  add_tunnel_routes
  add_server_bypass_route
  # exclude-маршруты (12,5k) — в фоне: src-selection станет корректным
  # по мере установки; до конца установки exclude-трафик временно пойдёт
  # в туннель (не ломает соединение, только лишний хоп).
  apply_exclude_routes add "$TBL_EXCLUDES" "$DEFAULT_GW" &
  log "pf anchor $PF_ANCHOR_NAME загружен ($TUN_DEV -> $SERVER_TUN_IP); exclude-маршруты ставятся в фоне"

  # state пишем ДО dns_save_and_set: та ДОПИСЫВАЕТ DNS_* в конец файла,
  # а write_state перезаписывает файл с нуля — иначе бэкап DNS теряется.
  START_OK="1"
  write_state

  if [[ "$SET_DNS" == "1" ]]; then
    dns_save_and_set
  fi

  log "Connected"

  if [[ "$FOREGROUND" == "1" ]]; then
    log "Supervising ssh process (foreground mode)"
    local rc=0
    wait "$SSH_PID" || rc=$?
    # ssh умер (или нас убили) — чистим маршрутную политику
    log "ssh process ended (rc=$rc) — cleaning up"
    stop_cleanup
    exit "$rc"
  fi

  printf '\nTUN: %s\nClient IP: %s\nServer TUN IP: %s\nSSH PID: %s\n\n' \
    "$TUN_DEV" "$CLIENT_TUN_IP" "$SERVER_TUN_IP" "$SSH_PID"
  printf 'Check:\n  ifconfig %s\n  curl -4 ifconfig.me\n\nStop:\n  sudo %s stop\n' "$TUN_DEV" "$0"
}

# stop_cleanup: снимает всё, что поставил start (вызывается из stop и из
# foreground-пути). Не дёргает lock (вызывающий уже держит или процесс умирает).
stop_cleanup() {
  # shellcheck disable=SC1090
  source "$STATE_FILE" 2>/dev/null || true

  # DNS восстанавливаем ПЕРВЫМ (пока есть state)
  if [[ -f "$STATE_FILE" ]]; then
    dns_restore || true
    del_server_bypass_route || true
    del_tunnel_routes || true
    # exclude-маршруты снимаем в фоне (12,5k × ~3 мс — не блокируем stop;
    # висящие после stop маршруты ведут себя как «direct», что корректно
    # для остановленного туннеля; дельты применяются в apply_diff).
    apply_exclude_routes delete "$TBL_EXCLUDES" &
  fi

  # ssh
  local pid="${SSH_PID:-}"
  if [[ -z "$pid" && -f "$STATE_DIR/ssh.pid" ]]; then
    pid="$(cat "$STATE_DIR/ssh.pid" 2>/dev/null || true)"
  fi
  if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i=0
    for ((i=0; i<25; i++)); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "$pid" 2>/dev/null || true
  fi

  pf_flush_anchor

  # utun не всегда исчезает при закрытии fd — уничтожаем явно
  if [[ -n "${TUN_DEV:-}" ]]; then
    ifconfig "${TUN_DEV}" destroy 2>/dev/null || ifconfig "${TUN_DEV}" down 2>/dev/null || true
  fi

  rm -f "$STATE_FILE" "$STATE_DIR/ssh.pid"
  log "Stopped"
}

stop_vpn() {
  need_root
  acquire_lock
  trap 'release_lock' EXIT
  stop_cleanup
}

status_vpn() {
  local pid="" host="" tun_dev="" sup=""
  # shellcheck disable=SC1090
  source "$STATE_FILE" 2>/dev/null || true
  pid="${SSH_PID:-}"
  if [[ -z "$pid" && -f "$STATE_DIR/ssh.pid" ]]; then
    pid="$(cat "$STATE_DIR/ssh.pid" 2>/dev/null || true)"
  fi
  if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    echo "Status: running"
    echo "PID: $pid"
    echo "Server: ${SSH_USER:-?}@${HOST:-?}:${SSH_PORT:-?}"
    echo "Server IP: ${SERVER_REAL_IP:-?}"
    echo "TUN: ${TUN_DEV:-?}"
    echo "Client IP: ${CLIENT_TUN_IP:-?}"
    echo "Server TUN IP: ${SERVER_TUN_IP:-?}"
    echo "SUPERVISED: ${SUPERVISED:-0}"
    echo "Policy: pf anchor $PF_ANCHOR_NAME (route-to ${TUN_DEV:-?})"
    if [[ -f "$TBL_EXCLUDES" ]]; then
      # файл таблицы и РЕАЛЬНОЕ содержимое pf-таблицы рядом: «persist file»
      # не перечитывает файл при reload — рассинхрон виден сразу.
      local pf_exc="" pf_inc=""
      pf_exc="$(pfctl -a "$PF_ANCHOR_NAME" -t sshtun_excludes -T show 2>/dev/null | grep -c / || true)"
      pf_inc="$(pfctl -a "$PF_ANCHOR_NAME" -t sshtun_includes -T show 2>/dev/null | grep -c / || true)"
      echo "Policy entries: excludes=$(grep -c . "$TBL_EXCLUDES" || true) includes=$(grep -c . "$TBL_INCLUDES" 2>/dev/null || true) (pf-live: ${pf_exc:-?}/${pf_inc:-?})"
    fi
    ifconfig "${TUN_DEV:-}" 2>/dev/null | sed -n '1,4p' || true
  else
    if [[ "${PHASE:-}" == "starting" && "${STARTED_AT:-}" =~ ^[0-9]+$ ]]; then
      local age=$(( $(date +%s) - STARTED_AT ))
      echo "Status: starting (подключение к ${SSH_USER:-?}@${HOST:-?}:${SSH_PORT:-?}, идёт ${age} с)"
      echo "Норма ~10-15 с; если зависло — sshtun down и повторите. Лог: /var/log/sshtun.log"
    else
      echo "Status: stopped"
    fi
  fi
  # остатки utun с адресами из наших сетей (активный не считаем leftover)
  local leftovers="" active_dev=""
  [[ -n "$pid" ]] && active_dev="${TUN_DEV:-}"
  leftovers="$(for d in $(utun_list); do
    [[ -n "$active_dev" && "$d" == "$active_dev" ]] && continue
    if ifconfig "$d" 2>/dev/null | grep -q "inet ${TUN_NET_A}.${TUN_NET_B}."; then printf '%s ' "$d"; fi
  done)"
  echo "Managed leftover utun devices: ${leftovers:-none}"
}

doctor_vpn() {
  echo "== state =="
  cat "$STATE_FILE" 2>/dev/null || echo "(no state)"
  echo
  echo "== last ssh log =="
  tail -n 15 "$SSH_LAST_LOG" 2>/dev/null || echo "(none)"
  echo
  echo "== live data-plane log =="
  tail -n 20 "$SSH_LOG" 2>/dev/null || echo "(none)"
  echo
  echo "== default route =="
  route -n get default 2>/dev/null | sed -n '1,8p' || true
  echo
  echo "== pf =="
  pfctl -s info 2>/dev/null | sed -n '1,3p' || echo "pfctl недоступен"
  pfctl -a "$PF_ANCHOR_NAME" -s rules 2>/dev/null || echo "(anchor пуст/не загружен)"
  echo "-- table sshtun_bypass --"
  pfctl -a "$PF_ANCHOR_NAME" -t sshtun_bypass -T show 2>/dev/null || echo "(таблица недоступна)"
  echo "-- rules+counters (Inbound/Outbound per rule) --"
  pfctl -a "$PF_ANCHOR_NAME" -vvsr 2>/dev/null | grep -E '^@|packets' | sed -n '1,40p' || true
  echo "-- states ( ESTABLISHED: flows висящие на правилах anchor'а ) --"
  pfctl -a "$PF_ANCHOR_NAME" -vvs state 2>/dev/null | grep -E '_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sed -n '1,20p' || echo "(state недоступны)"
  echo
  echo "== utun devices =="
  for d in $(utun_list); do
    ifconfig "$d" 2>/dev/null | grep -E '^(utun| *inet)' | sed -n '1,3p'
  done
  echo
  echo "== DNS (current service) =="
  local dev svc
  dev="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  svc="$(net_service_for_dev "$dev")"
  [[ -n "$svc" ]] && networksetup -getdnsservers "$svc" 2>/dev/null
}

cleanup_vpn() {
  need_root
  log "Cleaning up leftovers"
  # убить data-plane/ssh от старых запусков
  local pids=""
  pids="$(pgrep -f "sshtun-macos-tun|sshtun.*-w " 2>/dev/null || true)"
  local p=""
  for p in $pids; do
    [[ "$p" == "$$" ]] && continue
    kill "$p" 2>/dev/null || true
  done
  pf_flush_anchor
  local leftovers=""
  for d in $(utun_list); do
    if ifconfig "$d" 2>/dev/null | grep -q "inet ${TUN_NET_A}.${TUN_NET_B}."; then
      ifconfig "$d" destroy 2>/dev/null || ifconfig "$d" down 2>/dev/null || true
      leftovers+=" $d"
    fi
  done
  [[ -n "$leftovers" ]] && log "Убраны utun:$leftovers"
  rm -f "$STATE_FILE" "$STATE_DIR/ssh.pid"
  dns_restore || true
  log "Cleanup done"
}

# --- разбор аргументов -------------------------------------------------------
cmd="${1:-}"
shift 2>/dev/null || true
case "$cmd" in
  start)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --host) HOST="${2:-}"; shift 2 ;;
        --port) SSH_PORT="${2:-}"; shift 2 ;;
        --user) SSH_USER="${2:-}"; shift 2 ;;
        --key) KEY_FILE="${2:-}"; shift 2 ;;
        --tun-start) TUN_START="${2:-}"; shift 2 ;;
        --tun-end) TUN_END="${2:-}"; shift 2 ;;
        --mtu) TUN_MTU="${2:-}"; shift 2 ;;
        --exclude-file) EXCLUDE_FILES+=("${2:-}"); shift 2 ;;
        --route-file) ROUTE_FILES+=("${2:-}"); shift 2 ;;
        --foreground) FOREGROUND=1; shift ;;
        *) die "Неизвестная опция: $1" ;;
      esac
    done
    start_vpn ;;
  stop)  stop_vpn ;;
  status) status_vpn ;;
  doctor) doctor_vpn ;;
  pfprobe)
    # Диагностика pf/маршрутов живого туннеля (keepalive-расследование).
    need_root
    sip=""
    [[ -f "$STATE_FILE" ]] && { sip="$(awk -F= '/^SERVER_REAL_IP=/{gsub(/["'"'"']/,"",$2); print $2}' "$STATE_FILE" | tail -1)"; }
    echo "== route to server (${sip:-unknown}) =="
    [[ -n "$sip" ]] && route -n get "$sip" 2>/dev/null | grep -E 'route to|gateway|interface' || echo "(state пуст — туннель не поднимался)"
    echo "== route to 1.1.1.1 (catch-all halves?) =="
    route -n get 1.1.1.1 2>/dev/null | grep -E 'route to|gateway|interface'
    echo "== ip forwarding =="
    sysctl net.inet.ip.forwarding 2>/dev/null
    echo "== pf states (anchor) =="
    pfctl -a "$PF_ANCHOR_NAME" -s state 2>/dev/null | sed -n '1,15p' || echo "(anchor пуст)"
    echo "== pf rule counters =="
    pfctl -a "$PF_ANCHOR_NAME" -vvsr 2>/dev/null | grep -E '^@|Packets' | sed -n '1,50p' || true
    echo "== pf nat/binat (anchor) =="
    pfctl -a "$PF_ANCHOR_NAME" -s nat 2>/dev/null || echo "(нет translation-правил)"
    echo "== pf main ruleset =="
    pfctl -s rules 2>/dev/null | sed -n '1,15p'
    echo "== anchor.conf (generated) =="
    cat "$ANCHOR_CONF" 2>/dev/null || echo "(нет $ANCHOR_CONF)"
    ;;
  cleanup) cleanup_vpn ;;
  apply-diff) apply_diff ;;
  -h|--help|help|"") usage ;;
  *) die "Неизвестная команда: $cmd (см. $0 --help)" ;;
esac
