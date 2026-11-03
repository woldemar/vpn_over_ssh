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
    # порядок = семантика: include (равный префикс побеждает), exclude (LPM),
    # bypass (сервер/шлюз/link-local), multicast, IPv6-block, catch-all в tun.
    printf 'pass out quick inet from any to <sshtun_includes> route-to (%s %s)\n' "$TUN_DEV" "$SERVER_TUN_IP"
    printf 'pass out quick inet from any to <sshtun_excludes>\n'
    printf 'pass out quick inet from any to <sshtun_bypass>\n'
    printf 'pass out quick inet from any to 224.0.0.0/4\n'
    if [[ "$BLOCK_IPV6" == "1" ]]; then
      printf 'block drop quick out inet6 all\n'
    fi
    printf 'pass out quick inet route-to (%s %s) all\n' "$TUN_DEV" "$SERVER_TUN_IP"
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
  [[ -f "$PF_ANCHOR_FRAME" ]] || die "Нет $PF_ANCHOR_FRAME — запустите install_macos.sh"
  # таблицы должны существовать до загрузки правил
  : > "$TBL_EXCLUDES" 2>/dev/null || true
  pf_write_tables
  pf_write_anchor
  pf_ensure_enabled
  pfctl -a "$PF_ANCHOR_NAME" -f "$ANCHOR_CONF" 2>/dev/null \
    || die "pfctl не загрузил anchor (проверьте 'anchor \"$PF_ANCHOR_NAME\"' в /etc/pf.conf)"
}

pf_flush_anchor() {
  pfctl -a "$PF_ANCHOR_NAME" -F all >/dev/null 2>&1 || true
  if [[ "$HAD_PF_DISABLED" == "1" ]]; then
    pfctl -d >/dev/null 2>&1 || true
  fi
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
  pf_write_tables
  pf_write_anchor
  pfctl -a "$PF_ANCHOR_NAME" -f "$ANCHOR_CONF" >/dev/null \
    || die "pfctl reload anchor не удался"
  log "pf-таблицы пересобраны: excludes=$(grep -c . "$TBL_EXCLUDES" || true) includes=$(grep -c . "$TBL_INCLUDES" || true)"
}

# --- DNS --------------------------------------------------------------------
net_service_for_dev() { # en0 -> "Wi-Fi"
  networksetup -listnetworkserviceorder 2>/dev/null \
    | awk -v dev="$1" '
        /^\([0-9]+\)/ { svc=$0 }
        $0 ~ "Device: " dev "\\)" {
          sub(/^\([0-9]+\) /, "", svc)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", svc)
          print svc; exit
        }'
}

dns_save_and_set() {
  DNS_SERVICE="$(net_service_for_dev "$DEFAULT_DEV")"
  [[ -n "$DNS_SERVICE" ]] || { log "WARNING: не нашёл network-сервис для $DEFAULT_DEV — DNS не трогаю"; return 0; }
  local old_srv old_dom
  old_srv="$(networksetup -getdnsservers "$DNS_SERVICE" 2>/dev/null || true)"
  old_dom="$(networksetup -getsearchdomains "$DNS_SERVICE" 2>/dev/null || true)"
  {
    printf 'DNS_SERVICE=%q\n' "$DNS_SERVICE"
    printf 'DNS_OLD_SERVERS=%q\n' "$old_srv"
    printf 'DNS_OLD_DOMAINS=%q\n' "$old_dom"
  } >> "$STATE_FILE"
  # shellcheck disable=SC2086
  networksetup -setdnsservers "$DNS_SERVICE" $DNS_SERVERS >/dev/null \
    || { log "WARNING: setdnsservers не удался"; return 0; }
  networksetup -setsearchdomains "$DNS_SERVICE" Empty >/dev/null 2>&1 || true
  DNS_SAVED=1
  log "DNS $DNS_SERVICE -> $DNS_SERVERS"
}

dns_restore() {
  # shellcheck disable=SC1090
  source "$STATE_FILE" 2>/dev/null || return 0
  [[ -n "${DNS_SERVICE:-}" ]] || return 0
  if [[ "${DNS_OLD_SERVERS:-}" == There* || -z "${DNS_OLD_SERVERS:-}" ]]; then
    networksetup -setdnsservers "$DNS_SERVICE" Empty >/dev/null 2>&1 || true
  else
    # shellcheck disable=SC2086
    networksetup -setdnsservers "$DNS_SERVICE" ${DNS_OLD_SERVERS//$'\n'/ } >/dev/null 2>&1 || true
  fi
  if [[ "${DNS_OLD_DOMAINS:-}" == There* || -z "${DNS_OLD_DOMAINS:-}" ]]; then
    networksetup -setsearchdomains "$DNS_SERVICE" Empty >/dev/null 2>&1 || true
  else
    # shellcheck disable=SC2086
    networksetup -setsearchdomains "$DNS_SERVICE" ${DNS_OLD_DOMAINS//$'\n'/ } >/dev/null 2>&1 || true
  fi
  log "DNS $DNS_SERVICE восстановлен"
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
  trap 'release_lock' EXIT

  [[ -n "$HOST" ]] || die "--host не задан"
  [[ -f "$KEY_FILE" ]] || die "ключ не найден: $KEY_FILE"
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

  # адреса point-to-point + mtu
  ifconfig "$TUN_DEV" inet "$CLIENT_TUN_IP" "$SERVER_TUN_IP" mtu "$TUN_MTU" up \
    || die "ifconfig $TUN_DEV не удался"

  # маршрутная политика (pf)
  pf_load_anchor
  log "pf anchor $PF_ANCHOR_NAME загружен ($TUN_DEV -> $SERVER_TUN_IP)"

  if [[ "$SET_DNS" == "1" ]]; then
    dns_save_and_set
  fi

  START_OK="1"
  write_state
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

  # utun закроется сам при смерти ssh; если остался — down
  if [[ -n "${TUN_DEV:-}" ]]; then
    ifconfig "${TUN_DEV}" down 2>/dev/null || true
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
      echo "Policy entries: excludes=$(grep -c . "$TBL_EXCLUDES" || true) includes=$(grep -c . "$TBL_INCLUDES" 2>/dev/null || true)"
    fi
    ifconfig "${TUN_DEV:-}" 2>/dev/null | sed -n '1,4p' || true
  else
    echo "Status: stopped"
  fi
  # остатки utun с адресами из наших сетей
  local leftovers=""
  leftovers="$(for d in $(utun_list); do
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
  echo "== default route =="
  route -n get default 2>/dev/null | sed -n '1,8p' || true
  echo
  echo "== pf =="
  pfctl -s info 2>/dev/null | sed -n '1,3p' || echo "pfctl недоступен"
  pfctl -a "$PF_ANCHOR_NAME" -s rules 2>/dev/null || echo "(anchor пуст/не загружен)"
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
  # убить ssh от старых запусков
  local pids=""
  pids="$(pgrep -f "sshtun.*-w " 2>/dev/null || true)"
  local p=""
  for p in $pids; do
    [[ "$p" == "$$" ]] && continue
    kill "$p" 2>/dev/null || true
  done
  pf_flush_anchor
  local leftovers=""
  for d in $(utun_list); do
    if ifconfig "$d" 2>/dev/null | grep -q "inet ${TUN_NET_A}.${TUN_NET_B}."; then
      ifconfig "$d" down 2>/dev/null || true
      ifconfig "$d" destroy 2>/dev/null || true
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
  cleanup) cleanup_vpn ;;
  apply-diff) apply_diff ;;
  -h|--help|help|"") usage ;;
  *) die "Неизвестная команда: $cmd (см. $0 --help)" ;;
esac
