#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ==========================================================
# sshtun_full.sh — обёртка над sshtun_pool_client.sh
#
# Режим: FULL-TUNNEL. Весь IPv4-трафик идёт через сервер,
# кроме сетей из файлов исключений (они идут напрямую).
#
# Исключения читаются из ДВУХ файлов:
#   ~/sshtun/excludes.txt         — базовые (приватные + админские сети)
#   ~/sshtun/excludes-custom.txt  — ваш пополняемый список
#
# Команды:
#   up | start        поднять туннель
#   down | stop       остановить
#   restart           переподнять
#   status            состояние
#   doctor            диагностика
#   cleanup           убрать остатки после сбоев
#   add CIDR...       добавить сети в исключения (применит сразу,
#                     если туннель работает, и запомнит в файле)
#
# Запускать от обычного пользователя (sudo вызывается внутри).
# ==========================================================

# --- настройки (при необходимости меняются здесь или через env) ---
SERVER_HOST="${SERVER_HOST:-dvb.snee.su}"
SERVER_PORT="${SERVER_PORT:-65523}"
SSH_USER="${SSH_USER:-sshvpn}"
KEY_FILE="${KEY_FILE:-$HOME/.ssh/sshtun_ed25519}"
TUN_START="${TUN_START:-200}"
TUN_END="${TUN_END:-300}"
MTU="${MTU:-1400}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CLIENT_SCRIPT="${CLIENT_SCRIPT:-$SCRIPT_DIR/sshtun_pool_client.sh}"

EXCLUDES_DIR="${EXCLUDES_DIR:-$HOME/sshtun}"
BASE_EXCLUDES="$EXCLUDES_DIR/excludes.txt"
CUSTOM_EXCLUDES="$EXCLUDES_DIR/excludes-custom.txt"

log(){ echo "[$(date -Is)] $*"; }
die(){ echo "[ERROR] $*" >&2; exit 1; }

usage() {
  cat <<EOFUSAGE
Использование:
  $0 up            поднять туннель (full-tunnel + исключения)
  $0 down          остановить
  $0 restart       переподнять
  $0 status        состояние
  $0 doctor        диагностика
  $0 cleanup       очистка остатков
  $0 add CIDR...   добавить сети/адреса в исключения
                   (например: $0 add 203.0.113.0/24 198.51.100.7)

Исключения (идут напрямую, мимо туннеля):
  $BASE_EXCLUDES
  $CUSTOM_EXCLUDES
EOFUSAGE
}

check_client() {
  [[ -f "$CLIENT_SCRIPT" ]] || die "Не найден клиент: $CLIENT_SCRIPT"
}

check_excludes() {
  [[ -f "$BASE_EXCLUDES" ]] || die "Не найден файл исключений: $BASE_EXCLUDES"
  [[ -f "$CUSTOM_EXCLUDES" ]] || die "Не найден файл исключений: $CUSTOM_EXCLUDES"
}

check_key() {
  [[ -f "$KEY_FILE" ]] || die "Не найден ключ: $KEY_FILE
Создать: ssh-keygen -t ed25519 -f $KEY_FILE -N \"\" -C \"\$(whoami)-\$(hostname)\"
Затем добавить публичный ключ на сервер в /opt/sshtun_pool/authorized_keys"
}

# 1 — туннель работает, 0 — нет. State-файл лежит в /run/sshtun (root-only).
tun_is_running() {
  local pid=""
  pid="$(sudo -n bash -c 'source /run/sshtun/state 2>/dev/null; printf "%s" "${SSH_PID:-}"' 2>/dev/null || true)"
  [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

start_vpn() {
  check_client
  check_excludes
  check_key
  log "Поднимаю туннель: $SSH_USER@$SERVER_HOST:$SERVER_PORT (пул tun$TUN_START..tun$TUN_END)"
  sudo bash "$CLIENT_SCRIPT" start \
    --host "$SERVER_HOST" \
    --port "$SERVER_PORT" \
    --user "$SSH_USER" \
    --key "$KEY_FILE" \
    --tun-start "$TUN_START" \
    --tun-end "$TUN_END" \
    --mtu "$MTU" \
    --exclude-file "$BASE_EXCLUDES" \
    --exclude-file "$CUSTOM_EXCLUDES"
}

stop_vpn() {
  check_client
  sudo bash "$CLIENT_SCRIPT" stop
}

add_excludes() {
  [[ $# -ge 1 ]] || die "Укажите хотя бы одну сеть/адрес: $0 add 203.0.113.0/24"
  mkdir -p "$EXCLUDES_DIR"
  touch "$CUSTOM_EXCLUDES"

  local cidr=""
  for cidr in "$@"; do
    # одиночный адрес без префикса -> /32
    if [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      cidr="$cidr/32"
    fi
    [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] \
      || die "Не похоже на IPv4-подсеть/адрес: $cidr (нужно вида 203.0.113.0/24)"

    if grep -qxF "$cidr" "$CUSTOM_EXCLUDES"; then
      log "Уже есть в списке: $cidr"
    else
      echo "$cidr" >> "$CUSTOM_EXCLUDES"
      log "Записано в $CUSTOM_EXCLUDES: $cidr"
    fi

    # Туннель работает — применить маршрут сразу, без перезапуска.
    if tun_is_running; then
      local default_route gw dev
      default_route="$(ip -4 route show default | head -n1 || true)"
      gw="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$default_route")"
      dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$default_route")"
      if [[ -n "$dev" && -n "$gw" ]]; then
        sudo ip route replace "$cidr" via "$gw" dev "$dev"
        log "Маршрут применён сразу: $cidr via $gw dev $dev"
      elif [[ -n "$dev" ]]; then
        sudo ip route replace "$cidr" dev "$dev"
        log "Маршрут применён сразу: $cidr dev $dev"
      fi
    else
      log "Туннель сейчас не работает — маршрут подхватится при следующем 'up'"
    fi
  done
}

cmd="${1:-}"
case "$cmd" in
  up|start)   shift; start_vpn "$@" ;;
  down|stop)  shift; stop_vpn "$@" ;;
  restart)    shift; stop_vpn || true; start_vpn "$@" ;;
  status)     shift; check_client; sudo bash "$CLIENT_SCRIPT" status "$@" ;;
  doctor)     shift; check_client; sudo bash "$CLIENT_SCRIPT" doctor "$@" ;;
  cleanup)    shift; check_client; sudo bash "$CLIENT_SCRIPT" cleanup "$@" ;;
  add)        shift; add_excludes "$@" ;;
  -h|--help|help|"") usage ;;
  *) die "Неизвестная команда: $cmd (см. $0 --help)" ;;
esac
