#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ==========================================================
# sshtun_full.sh — обёртка над sshtun_pool_client.sh
#
# Режим: FULL-TUNNEL. Весь IPv4-трафик идёт через сервер,
# кроме сетей из файлов исключений (они идут напрямую).
#
# Файлы маршрутной политики (каталог ~/sshtun):
#   excludes.txt           — базовые исключения (RFC1918 + админские сети)
#   excludes-custom.txt    — ваш пополняемый список исключений
#   excludes-as.txt        — ИСТОЧНИКИ: токены AS (AS9009), по одному на строку
#   excludes-country.txt   — ИСТОЧНИКИ: токены стран (ru, de, us)
#   includes-force.txt     — принудительно В ТУННЕЛЬ (приоритет над excludes)
#   generated/             — АВТОГЕН: развёрнутые префиксы AS/стран (не править;
#                            обновляются 'sshtun refresh' / автоматически при 'up')
#   servers/<имя>.conf     — профили серверов (multihop-библиотека; активный
#                            профиль ставится в server.conf командой 'server use')
#
# Приоритет: ядро выбирает по длине префикса (LPM) — более точный префикс
# побеждает независимо от файла. На равных префиксах побеждает force-файл.
#
# Команды:
#   up | start          поднять туннель; если установлен systemd-юнит
#                       sshtun.service — ЧЕРЕЗ СЛУЖБУ (с досмотром: переживёт
#                       сон/обрыв/рестарт сервера), иначе напрямую
#   up --background     поднять напрямую, БЕЗ досмотра (только явный запрос:
#                       после сна/обрыва такой туннель сам не переподнимется)
#   up --foreground     поднять и не выходить (режим systemd: досмотр ssh,
#                       при падении — exit 1 для Restart=always)
#   down | stop         остановить
#   restart             переподнять
#   status              состояние
#   doctor              диагностика
#   cleanup             убрать остатки после сбоев
#   exclude add CIDR... [-- комментарий]
#                       в исключения (direct, мимо туннеля)
#   exclude del CIDR... убрать из пользовательских исключений
#   include add CIDR... [-- комментарий]
#                       принудительно завернуть сети в туннель
#   include del CIDR... убрать сети из include-списка
#   fetch-as AS...      исключить префиксы AS (RIPEstat; --irr — через bgpq4;
#                       --remove AS — убрать AS из списка). Токены — в
#                       excludes-as.txt, префиксы — в generated/excludes-as.txt
#   fetch-country CC... исключить префиксы стран (ipdeny.com, коды ISO;
#                       --remove CC — убрать страну из списка)
#   refresh             перекачать все автогенные списки
#   list                показать эффективную маршрутную политику
#   server list         список профилей серверов ('*' — активный)
#   server add NAME HOST [--port N] [--user U] [--key FILE]
#                       [--tun-start N] [--tun-end N] [--mtu N]
#                       [--net-a A] [--net-b B] [-- комментарий]
#   server use NAME     переключиться на профиль (переподнимет туннель)
#   server del NAME     удалить профиль (активный удалить нельзя)
#   server rename OLD NEW  переименовать профиль (активный тоже)
#   NAME                сокращение от 'server use NAME' (существующий профиль;
#                       имена, совпадающие с командами, сокращением не работают)
#
# Файлы AS/стран — источники-токены (править руками или командами выше);
# развёрнутые префиксы кладутся в ~/sshtun/generated/ и там же кэшируются
# между обновлениями (при отсутствии сети 'up' использует кэш).
#
# Устаревшие алиасы (работают, но подсказывают миграцию):
#   add/del             = exclude add/del
#   force-add/force-del = include add/del
#
# Запускать от обычного пользователя (sudo вызывается внутри).
# ==========================================================

# --- настройки (при необходимости меняются здесь или через env) ---
# SERVER_HOST намеренно НЕ имеет дефолта в коде: реальный адрес сервера
# задаётся локально — через env SERVER_HOST или файл ~/sshtun/server.conf
# (создаётся установщиком из шаблона, в репозиторий не коммитится).
# Адрес и параметры, заданные через env (имеют приоритет над любыми
# файлами) — запоминаем до чтения server.conf, чтобы 'server use' мог
# перечитать конфиг свежим и при этом не перекрыть явный env.
SERVER_HOST_FROM_ENV="${SERVER_HOST:-}"
SERVER_PORT_FROM_ENV="${SERVER_PORT:-}"
SSH_USER_FROM_ENV="${SSH_USER:-}"
KEY_FILE_FROM_ENV="${KEY_FILE:-}"
TUN_START_FROM_ENV="${TUN_START:-}"
TUN_END_FROM_ENV="${TUN_END:-}"
MTU_FROM_ENV="${MTU:-}"
TUN_NET_A_FROM_ENV="${TUN_NET_A:-}"
TUN_NET_B_FROM_ENV="${TUN_NET_B:-}"
SERVER_HOST="${SERVER_HOST:-}"
SERVER_PORT="${SERVER_PORT:-65523}"
SSH_USER="${SSH_USER:-sshvpn}"
KEY_FILE="${KEY_FILE:-$HOME/.ssh/sshtun_ed25519}"
TUN_START="${TUN_START:-200}"
TUN_END="${TUN_END:-250}"
MTU="${MTU:-1400}"
# Адресация туннельной пары: клиент вычисляет свою/серверную IP из номера
# tun (как и серверный apply-network.sh). Дефолт 10.250/16 должен совпадать
# с серверным TUN_NET_A/TUN_NET_B; сервер с другой адресацией (например,
# второй сервер в 10.251/16) задаётся в профиле (--net-a/--net-b).
# Диапазон tun по умолчанию 200..250 — осознанный компромисс: 0..~15
# занимает система macOS, 100..199 может занимать NetworkManager (tun/tap
# подключения) на Linux-хостах, а macOS не умеет utun > 255 вообще
# («Tunnel device open failed»).
TUN_NET_A="${TUN_NET_A:-10}"
TUN_NET_B="${TUN_NET_B:-250}"

# Директория скрипта с разрешением симлинков: обёртка может быть
# установлена как symlink в /usr/local/bin/sshtun -> /opt/sshtun_client/.
SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_PATH" ]]; do
  SCRIPT_LINK_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd -P)"
  SCRIPT_PATH="$(readlink "$SCRIPT_PATH")"
  [[ "$SCRIPT_PATH" != /* ]] && SCRIPT_PATH="$SCRIPT_LINK_DIR/$SCRIPT_PATH"
done
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd -P)"
UNAME_S="${UNAME_S:-$(uname -s 2>/dev/null || echo Linux)}"
# State-файл работающего туннеля лежит в root-only каталоге: /run на Linux,
# /var/run на macOS (физически /private/var/run).
RUNTIME_STATE_DIR="${RUNTIME_STATE_DIR:-/run/sshtun}"
# Бэкенд: тот же контракт CLI/state. macOS-вариант гоняет маршруты через
# pfctl (route-to), DNS через networksetup, lock через mkdir (flock нет).
if [[ "$UNAME_S" == "Darwin" ]]; then
  CLIENT_SCRIPT="${CLIENT_SCRIPT:-$SCRIPT_DIR/sshtun_macos.sh}"
  RUNTIME_STATE_DIR="/var/run/sshtun"
  MACOS_SERVICE="${MACOS_SERVICE:-com.sshtun.client}"
  # Единственная root-точка на macOS: root-owned хелпер, разрешённый в
  # sudoers (NOPASSWD). Прямого «sudo bash» на Darwin не вызываем никогда.
  # Хелпер живёт в /opt (root-only); при запуске обёртки прямо из репозитория
  # (где sshtun-root отсутствует) — fallback на /opt.
  ROOT_HELPER="${ROOT_HELPER:-$SCRIPT_DIR/sshtun-root}"
  [[ -f "$ROOT_HELPER" || "$UNAME_S" != "Darwin" ]] || {
    [[ -f /opt/sshtun_client/sshtun-root ]] && ROOT_HELPER=/opt/sshtun_client/sshtun-root
  }
else
  CLIENT_SCRIPT="${CLIENT_SCRIPT:-$SCRIPT_DIR/sshtun_pool_client.sh}"
fi
# env.conf (SSH_BIN и др.) — пишет install_macos.sh. shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/env.conf" ]] && source "$SCRIPT_DIR/env.conf"

EXCLUDES_DIR="${EXCLUDES_DIR:-$HOME/sshtun}"
# Профили серверов: библиотека в servers/*.conf + активный server.conf.
# server.conf остаётся рабочим конфигом (backward compat: служба и env-логика
# его не замечают) — 'server use <name>' атомарно устанавливает профиль в него.
SERVER_CONF="$EXCLUDES_DIR/server.conf"
SERVERS_DIR="$EXCLUDES_DIR/servers"
# Активный профиль (server.conf, в т.ч. старый ручной) читается после
# определения функций — см. reload_server_conf вызов перед dispatch: env
# побеждает, из файла подтягиваются все параметры сервера.
BASE_EXCLUDES="$EXCLUDES_DIR/excludes.txt"
CUSTOM_EXCLUDES="$EXCLUDES_DIR/excludes-custom.txt"
AS_EXCLUDES="$EXCLUDES_DIR/excludes-as.txt"
COUNTRY_EXCLUDES="$EXCLUDES_DIR/excludes-country.txt"
FORCE_INCLUDES="$EXCLUDES_DIR/includes-force.txt"
# Развёрнутые префиксы источников — отдельно от файлов-токенов: токены правят
# руками/командами, префиксы скачиваются и лежат в generated/ (клиент читает их).
GENERATED_DIR="${GENERATED_DIR:-$EXCLUDES_DIR/generated}"
AS_GENERATED="$GENERATED_DIR/excludes-as.txt"
COUNTRY_GENERATED="$GENERATED_DIR/excludes-country.txt"

# Таблицы policy routing — должны совпадать с клиентом (он пишет их в state).
POLICY_TABLE_DIRECT="${POLICY_TABLE_DIRECT:-200}"

# GNU date умеет -Is, BSD (macOS) — нет: собираем вручную, %z -> +HH:MM.
ts_iso(){ date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null | sed -E 's/([0-9]{2})$/:\1/' || true; }
log(){ echo "[$(ts_iso)] $*" 2>/dev/null || true; }
die(){ echo "[ERROR] $*" >&2 || true; exit 1; }

# Под systemd обёртка работает от root, а файлы данных должен править
# пользователь — возвращаем владельцу ~/sshtun и читаемые права (работает
# и для generated/: ссылка — всегда на каталог данных, не на родителя).
restore_owner() { # path
  # chown --reference и stat -c — GNU-специфика; на macOS stat -f.
  local owner=""
  owner="$(stat -c '%U:%G' "$EXCLUDES_DIR" 2>/dev/null || stat -f '%Su:%Sg' "$EXCLUDES_DIR" 2>/dev/null || true)"
  [[ -n "$owner" ]] && chown "$owner" "$1" 2>/dev/null || true
  if [[ -d "$1" ]]; then
    chmod 0755 "$1" 2>/dev/null || true
  else
    chmod 0644 "$1" 2>/dev/null || true
  fi
}

# sed -i на BSD требует аргумент суффикса бэкапа (sed -i '').
sed_i() { # file expr
  local f="$1"; shift
  if [[ "$UNAME_S" == "Darwin" ]]; then
    sed -i '' "$@" "$f"
  else
    sed -i "$@" "$f"
  fi
}

usage() {
  cat <<EOFUSAGE
Использование:
  $0 up                 поднять туннель (full-tunnel + исключения); если
                        установлен systemd-юнит sshtun — ЧЕРЕЗ СЛУЖБУ (досмотр:
                        переживёт сон/обрыв). Без досмотра: up --background
  $0 up --background    поднять напрямую, без досмотра (после сна сам не поднимется)
  $0 down               остановить
  $0 restart            переподнять
  $0 status             состояние
  $0 doctor             диагностика
  $0 cleanup            очистка остатков
  $0 exclude add CIDR... [-- комментарий]    в исключения (напрямую, мимо туннеля)
  $0 exclude del CIDR...    убрать из пользовательских исключений
  $0 include add CIDR... [-- комментарий]    принудительно в туннель (даже если в exclude)
  $0 include del CIDR...    убрать из include-списка
  $0 fetch-as AS... [--irr] [-- комментарий]   исключить префиксы AS (RIPEstat / bgpq4)
  $0 fetch-as --remove AS... убрать AS из автогенного списка
  $0 fetch-country CC... [-- комментарий]  исключить префиксы стран (ipdeny.com)
  $0 fetch-country --remove CC...  убрать страну из списка
  $0 refresh            перекачать все автогенные списки
  $0 list               показать маршрутную политику
  $0 server list        список профилей серверов ('*' — активный)
  $0 server add NAME HOST [--port N] [--user U] [--key FILE]
                        [--tun-start N] [--tun-end N] [--mtu N]
                        [--net-a A] [--net-b B] [-- комментарий]
                        добавить профиль сервера
                        (--net-a/--net-b — адресация туннельной пары,
                        должна совпадать с серверными TUN_NET_A/TUN_NET_B)
  $0 server use NAME    переключиться на профиль (туннель переподнимется,
                        если работает; иначе применится при следующем up)
  $0 server del NAME    удалить профиль (активный удалить нельзя)
  $0 server rename OLD NEW   переименовать профиль (активный тоже; туннель не тронет)
  $0 NAME               сокращение от 'server use NAME' (существующий профиль)

Устаревшие алиасы: add/del = exclude add/del; force-add/force-del = include add/del.

Исключения (идут напрямую, мимо туннеля):
  $BASE_EXCLUDES
  $CUSTOM_EXCLUDES
  $AS_EXCLUDES        (токены AS; префиксы разворачиваются в $AS_GENERATED)
  $COUNTRY_EXCLUDES   (токены стран; префиксы — в $COUNTRY_GENERATED)

Принудительно в туннель (приоритет на равных префиксах):
  $FORCE_INCLUDES

Приоритет: более длинный префикс побеждает всегда (LPM);
на равных префиксах force-файл побеждает exclude-файлы.
EOFUSAGE
}

check_client() {
  [[ -f "$CLIENT_SCRIPT" ]] || die "Не найден клиент: $CLIENT_SCRIPT"
  if [[ "$UNAME_S" == "Darwin" && ! -f "$ROOT_HELPER" ]]; then
    die "Не найден root-хелпер: $ROOT_HELPER (переустановите install_macos.sh)"
  fi
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

# 1 — туннель работает, 0 — нет. State-файл лежит в root-only каталоге
# (RUNTIME_STATE_DIR). kill -0 не подходит: sshd-клиент работает от root, и
# обычный пользователь получает EPERM. Linux: /proc (читаем всем при
# стандартном hidepid); macOS: ps видит чужие процессы.
# shellcheck disable=SC1090
state_var() { # VAR... -> значения через пробел
  if [[ "$UNAME_S" == "Darwin" ]]; then
    sudo -n "$ROOT_HELPER" state-var "$@" 2>/dev/null || true
    return 0
  fi
  sudo -n bash -c '
    s="$1"; shift
    source "$s" 2>/dev/null
    while (($#)); do
      eval "printf \"%s\" \"\${$1:-}\""
      shift
      (($# > 0)) && printf " "
    done
  ' _ "$RUNTIME_STATE_DIR/state" "$@" 2>/dev/null || true
}

# Запуск подкоманд бэкенда с правами root.
client_cmd() { # args...
  if [[ "$UNAME_S" == "Darwin" ]]; then
    sudo -n "$ROOT_HELPER" backend-run "$@"
  else
    sudo bash "$CLIENT_SCRIPT" "$@"
  fi
}

tun_is_running() {
  local pid=""
  pid="$(state_var SSH_PID)"
  [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] || return 1
  if [[ "$UNAME_S" == "Darwin" ]]; then
    ps -p "$pid" -o pid= >/dev/null 2>&1
    return $?
  fi
  [[ -d "/proc/$pid" ]] && return 0
  kill -0 "$pid" 2>/dev/null
}

# CIDR-ы (без комментариев и пустых строк), отсортированные уникальные.
list_entries() {
  [[ -f "$1" ]] || return 0
  sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -u
}

# Источники автогенного файла из его шапки. Вывод sed читаем целиком до
# awk: пайп 'sed | head' — SIGPIPE-ловушка под pipefail.
managed_sources() {
  [[ -f "$1" ]] || return 0
  local out
  out="$(sed -n 's/^# sshtun-managed-sources:[[:space:]]*//p' "$1")"
  awk 'NR==1{print; exit}' <<<"$out"
}

# Нормализация аргумента в CIDR: адрес без префикса -> /32; валидация формата.
normalize_cidr() {
  local cidr="$1"
  if [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    cidr="$cidr/32"
  fi
  [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] \
    || die "Не похоже на IPv4-подсеть/адрес: $1 (нужно вида 203.0.113.0/24)"
  printf '%s' "$cidr"
}

# Разобрать аргументы команд add/del: CIDR... [-- комментарий].
# nameref: _cidrs (массив CIDR), _comment (строка, может быть пустой).
parse_cidrs_comment() {
  local -n _cidrs="$1"
  local -n _comment="$2"
  shift 2
  _cidrs=()
  _comment=""
  local seen_ddash=0 arg=""
  for arg in "$@"; do
    if (( seen_ddash == 0 )) && [[ "$arg" == "--" ]]; then
      seen_ddash=1
      continue
    fi
    if (( seen_ddash == 1 )); then
      _comment+="${_comment:+ }$arg"
    else
      _cidrs+=("$arg")
    fi
  done
}

# Значение ключа KEY=... из профиля/конфига (последняя строка). Файл не
# source'ится нарочно: иначе профиль мог бы выполнить произвольный код от
# имени пользователя, запустившего sshtun.
conf_key() { # file key
  local out=""
  out="$(sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -n1 | tr -d '[:space:]')"
  printf '%s' "$out"
}

# Перечитать параметры сервера из активного server.conf. Нужна после
# 'server use': переменные скрипта прочитаны на старте, а профиль только
# что сменился. env (сохранён в *_FROM_ENV на старте) побеждает файл;
# отсутствующие в файле ключи оставляем дефолтными.
reload_server_conf() {
  [[ -f "$SERVER_CONF" ]] || return 0
  SERVER_HOST="${SERVER_HOST_FROM_ENV:-$(conf_key "$SERVER_CONF" SERVER_HOST)}"
  SERVER_PORT="${SERVER_PORT_FROM_ENV:-$(conf_key "$SERVER_CONF" SERVER_PORT)}"
  [[ -n "$SERVER_PORT" ]] || SERVER_PORT=65523
  SSH_USER="${SSH_USER_FROM_ENV:-$(conf_key "$SERVER_CONF" SSH_USER)}"
  [[ -n "$SSH_USER" ]] || SSH_USER=sshvpn
  KEY_FILE="${KEY_FILE_FROM_ENV:-$(conf_key "$SERVER_CONF" KEY_FILE)}"
  [[ -n "$KEY_FILE" ]] || KEY_FILE="$HOME/.ssh/sshtun_ed25519"
  TUN_START="${TUN_START_FROM_ENV:-$(conf_key "$SERVER_CONF" TUN_START)}"
  [[ -n "$TUN_START" ]] || TUN_START=200
  TUN_END="${TUN_END_FROM_ENV:-$(conf_key "$SERVER_CONF" TUN_END)}"
  [[ -n "$TUN_END" ]] || TUN_END=300
  MTU="${MTU_FROM_ENV:-$(conf_key "$SERVER_CONF" MTU)}"
  [[ -n "$MTU" ]] || MTU=1400
  TUN_NET_A="${TUN_NET_A_FROM_ENV:-$(conf_key "$SERVER_CONF" TUN_NET_A)}"
  [[ -n "$TUN_NET_A" ]] || TUN_NET_A=10
  TUN_NET_B="${TUN_NET_B_FROM_ENV:-$(conf_key "$SERVER_CONF" TUN_NET_B)}"
  [[ -n "$TUN_NET_B" ]] || TUN_NET_B=250
}

# Имя активного профиля — маркер '# sshtun-profile: NAME', который 'server use'
# пишет в server.conf. Пусто — server.conf сделан/правлен вручную.
active_profile() {
  local marker=""
  [[ -f "$SERVER_CONF" ]] || return 0
  marker="$(sed -n 's/^# sshtun-profile:[[:space:]]*//p' "$SERVER_CONF" 2>/dev/null | tail -n1 | tr -d '[:space:]')"
  printf '%s' "$marker"
}

# Комментарий профиля из его шапки ('# comment: ...' пишет 'server add').
profile_comment() { # file
  local out=""
  out="$(sed -n 's/^# comment:[[:space:]]*//p' "$1" 2>/dev/null | tail -n1)"
  printf '%s' "$out"
}

# Строка-описание активного сервера для status: профиль, а иначе откуда адрес.
profile_display() {
  if [[ -n "$SERVER_HOST_FROM_ENV" ]]; then
    printf 'env SERVER_HOST=%s (перекрывает профили)' "$SERVER_HOST_FROM_ENV"
    return 0
  fi
  local name="" host=""
  name="$(active_profile)"
  host="$(conf_key "$SERVER_CONF" SERVER_HOST)"
  if [[ -n "$name" ]]; then
    printf '%s (%s)' "$name" "${host:-?}"
  elif [[ -n "$host" ]]; then
    printf '(server.conf без профиля) %s' "$host"
  else
    printf '(не задан — см. sshtun server add)'
  fi
}

# Атомарно установить профиль активным: временный файл + mv (никто не поймает
# обрезанный server.conf), владелец/права — как у ~/sshtun.
activate_profile() { # name
  local name="$1" src="$SERVERS_DIR/$1.conf" tmp=""
  mkdir -p "$EXCLUDES_DIR"
  tmp="$(mktemp "$EXCLUDES_DIR/.server.conf.XXXXXX")"
  {
    printf '# SSHTUN: активный профиль сервера (установлено: sshtun server use %s)\n' "$name"
    printf '# sshtun-profile: %s\n' "$name"
    cat "$src"
  } > "$tmp"
  mv -f "$tmp" "$SERVER_CONF"
  restore_owner "$SERVER_CONF"
}

server_list() {
  echo "=== СЕРВЕРЫ (профили: $SERVERS_DIR/*.conf; '*' — активный):"
  if [[ ! -d "$SERVERS_DIR" ]] || ! ls "$SERVERS_DIR"/*.conf >/dev/null 2>&1; then
    echo "    (профилей нет — добавьте: sshtun server add NAME HOST [--port N] [--user U] [--key FILE] [--mtu N] [-- комментарий])"
  else
    local f="" name="" host="" port="" comment="" cur=""
    cur="$(active_profile)"
    for f in "$SERVERS_DIR"/*.conf; do
      name="$(basename "$f" .conf)"
      host="$(conf_key "$f" SERVER_HOST)"
      port="$(conf_key "$f" SERVER_PORT)"; port="${port:-65523}"
      comment="$(profile_comment "$f")"
      printf '    %s %-20s %-30s порт %s' "$([[ "$name" == "$cur" ]] && printf '*' || printf ' ')" "$name" "${host:-?}" "$port"
      [[ -n "$comment" ]] && printf '   # %s' "$comment"
      printf '\n'
    done
  fi
  echo
  echo "    Активный: $(profile_display)"
  echo "    Переключение: sshtun server use NAME (туннель переподнимется, если работает)"
  if [[ -n "$SERVER_HOST_FROM_ENV" ]]; then
    echo "    ВНИМАНИЕ: SERVER_HOST задан через env — перекрывает любые профили/файлы."
  fi
}

server_add() {
  local name="${1:-}" host="${2:-}"
  [[ -n "$name" && -n "$host" ]] \
    || die "Укажите имя и адрес: $0 server add NAME HOST [--port N] [--user U] [--key FILE] [--tun-start N] [--tun-end N] [--mtu N] [-- комментарий]"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] \
    || die "Недопустимое имя профиля: $name (допустимы [A-Za-z0-9_-], начало с буквы/цифры)"
  [[ "$host" != *[[:space:]]* ]] || die "Адрес не должен содержать пробелов: $host"
  shift 2  # name и host гарантированно есть (проверка выше)
  local port="$SERVER_PORT" user="$SSH_USER" key="$KEY_FILE" mtu="$MTU"
  local tstart="$TUN_START" tend="$TUN_END" comment="" a=""
  local net_a="$TUN_NET_A" net_b="$TUN_NET_B"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port)      port="${2:-}"; shift 2 ;;
      --user)      user="${2:-}"; shift 2 ;;
      --key)       key="${2:-}"; shift 2 ;;
      --tun-start) tstart="${2:-}"; shift 2 ;;
      --tun-end)   tend="${2:-}"; shift 2 ;;
      --mtu)       mtu="${2:-}"; shift 2 ;;
      --net-a)     net_a="${2:-}"; shift 2 ;;
      --net-b)     net_b="${2:-}"; shift 2 ;;
      --)          shift; comment=""
                   for a in "$@"; do comment+="${comment:+ }$a"; done
                   break ;;
      *) die "Неизвестная опция: $1" ;;
    esac
  done
  local dest="$SERVERS_DIR/$name.conf"
  [[ ! -f "$dest" ]] || die "Профиль '$name' уже существует: $dest (убрать: sshtun server del $name)"
  mkdir -p "$SERVERS_DIR"
  restore_owner "$SERVERS_DIR"
  local comment_line=""
  [[ -n "$comment" ]] && comment_line="# comment: $comment"
  cat > "$dest" <<EOFPROFILE
# SSHTUN-профиль сервера '$name'. Файл данных — в git не коммитится.
# Применить: sshtun server use $name
$comment_line
SERVER_HOST=$host
SERVER_PORT=$port
SSH_USER=$user
KEY_FILE=$key
TUN_START=$tstart
TUN_END=$tend
MTU=$mtu
# Адресация туннельной пары — должна совпадать с серверными
# TUN_NET_A/TUN_NET_B (у второго сервера своя, чтобы не пересекаться).
TUN_NET_A=$net_a
TUN_NET_B=$net_b
EOFPROFILE
  restore_owner "$dest"
  log "Профиль '$name' создан: $dest"
  log "Переключиться: sshtun server use $name"
}

server_del() {
  local name="${1:-}"
  [[ -n "$name" ]] || die "Укажите имя профиля: $0 server del NAME"
  local f="$SERVERS_DIR/$name.conf"
  [[ -f "$f" ]] || die "Профиль не найден: $f"
  [[ "$(active_profile)" != "$name" ]] \
    || die "Профиль '$name' активен — сначала переключитесь: sshtun server use ДРУГОЕ_ИМЯ"
  rm -f "$f"
  log "Профиль '$name' удалён"
}

server_rename() { # old new
  local old="${1:-}" new="${2:-}"
  [[ -n "$old" && -n "$new" ]] || die "Укажите: $0 server rename СТАРОЕ_ИМЯ НОВОЕ_ИМЯ"
  [[ "$new" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] \
    || die "Недопустимое имя профиля: $new (допустимы [A-Za-z0-9_-], начало с буквы/цифры)"
  local src="$SERVERS_DIR/$old.conf" dst="$SERVERS_DIR/$new.conf"
  [[ -f "$src" ]] || die "Профиль не найден: $src"
  [[ ! -f "$dst" ]] || die "Профиль '$new' уже существует: $dst"
  # Шапку профиля (строки с комментариями) приводим к новому имени —
  # там шаблонные 'server OLD' и 'server use OLD'. Содержимое не трогаем.
  sed_i "$src" "/^#/s/'$old'/'$new'/g; /^#/s/use $old\$/use $new/"
  mv -f "$src" "$dst"
  restore_owner "$dst"
  if [[ "$(active_profile)" == "$old" ]]; then
    # Активный профиль: обновить маркер в server.conf. Параметры сервера
    # не меняются — переподнимать туннель не нужно.
    activate_profile "$new"
    log "Активный профиль переименован: $old -> $new (маркер обновлён, туннель не тронут)"
  else
    log "Профиль переименован: $old -> $new"
  fi
}

# Содержимое активного server.conf совпадает с профилем (без двух строк
# служебной шапки)? Нужно, чтобы 'server use' замечал ручные правки
# профиля после активации и переустанавливал конфиг, а не молчал «уже активен».
profile_is_active_content() { # name -> 0 если server.conf == профиль
  local src="$SERVERS_DIR/$1.conf"
  [[ -f "$SERVER_CONF" && -f "$src" ]] || return 1
  diff -q <(tail -n +3 "$SERVER_CONF") "$src" >/dev/null 2>&1
}

server_use() {
  local name="${1:-}"
  [[ -n "$name" ]] || die "Укажите имя профиля: $0 server use NAME (список: sshtun server list)"
  local src="$SERVERS_DIR/$name.conf"
  [[ -f "$src" ]] || die "Профиль не найден: $src (добавить: sshtun server add $name HOST)"
  local host=""
  host="$(conf_key "$src" SERVER_HOST)"
  [[ -n "$host" ]] || die "В профиле '$name' нет SERVER_HOST: $src"
  if [[ "$(active_profile)" == "$name" ]] && profile_is_active_content "$name"; then
    log "Профиль '$name' уже активен ($host)"
    return 0
  fi
  [[ -z "$SERVER_HOST_FROM_ENV" ]] \
    || log "ВНИМАНИЕ: SERVER_HOST задан через env — файл/профиль им перекрывается"
  activate_profile "$name"
  reload_server_conf
  log "Переключено на '$name' ($SERVER_HOST)"
  if tun_is_running; then
    log "Туннель работает — переподнимаю на новом сервере"
    restart_vpn
  else
    log "Туннель не работает — профиль применится при 'sshtun up'"
  fi
}

# Есть ли CIDR в файле (сравнение по первому токену строки, комментарии
# в строках вида "CIDR # комментарий" не мешают).
cidr_line_exists() { # file cidr
  awk -v c="$2" '{
    line = $0
    sub(/^[[:space:]]*/, "", line)
    sub(/[[:space:]]*#.*/, "", line)
    sub(/[[:space:]]*$/, "", line)
    if (line == c) found = 1
  } END { exit !found }' "$1"
}

# Вывести файл без строк, чей первый токен равен CIDR.
remove_cidr_lines() { # file cidr
  awk -v c="$2" '{
    line = $0
    sub(/^[[:space:]]*/, "", line)
    sub(/[[:space:]]*#.*/, "", line)
    sub(/[[:space:]]*$/, "", line)
    if (line == c) next
    print
  }' "$1"
}

# Загрузить все exclude-CIDR из всех файлов в ассоциативный массив (по ссылке).
# Один проход по файлам вместо fork-grep на каждый CIDR: для диффов
# в тысячи строк это разница между 0.3 с и минутами.
# Для AS/стран берём generated/-кэш: файлы-токены префиксов не содержат.
load_exclude_set() {
  local -n _out="$1"
  local f="" e=""
  for f in "$BASE_EXCLUDES" "$CUSTOM_EXCLUDES" "$AS_GENERATED" "$COUNTRY_GENERATED"; do
    [[ -f "$f" ]] || continue
    while IFS= read -r e; do
      [[ -n "$e" ]] && _out["$e"]=1
    done < <(list_entries "$f")
  done
}

# Массовое runtime-применение direct-изменений одним netlink-батчем.
# stdin: строки "add CIDR" / "del CIDR". Маршруты живут в таблице
# POLICY_TABLE_DIRECT (там — вся политика, main не трогается). del
# пропускается, если CIDR ещё встречается в другом exclude-файле.
# Без работающего туннеля — только запись в файл (подхватится при 'up').
apply_direct_changes() {
  local ops=() line=""
  while IFS= read -r line; do
    [[ -n "$line" ]] && ops+=("$line")
  done
  ((${#ops[@]} > 0)) || return 0

  if ! tun_is_running; then
    log "Туннель не работает — маршруты подхватятся при следующем 'up'"
    return 0
  fi

  if [[ "$UNAME_S" == "Darwin" ]]; then
    # macOS: diff не нужен — бэкенд пересобирает pf-таблицы из файлов политики
    # (exclude-файлы обёртка уже перезаписала).
    printf '%s\n' "${ops[@]}" | sudo -n "$ROOT_HELPER" backend-run apply-diff \
      && log "Применено изменений маршрутов: ${#ops[@]}" \
      || log "WARNING: apply-diff не удался"
    return 0
  fi

  local table
  table="$(policy_table_direct_runtime)"

  local default_route routes_out gw dev
  routes_out="$(ip -4 route show default 2>/dev/null)" || true
  default_route="$(awk 'NR==1{print; exit}' <<<"$routes_out")"
  gw="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$default_route")"
  dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$default_route")"
  if [[ -z "$dev" ]]; then
    log "Не найден default route — маршруты подхватятся при следующем 'up'"
    return 0
  fi

  local tmp op cidr has_add=0
  tmp="$(mktemp)" || return 1
  local -A excl=()
  load_exclude_set excl
  # Один редирект на цикл: построчное ">> "$tmp"" стоит ~7 мс/строку на хостах
  # с аудитом открытий (тысячи строк diff после refresh => минуты).
  {
    for line in "${ops[@]}"; do
      op="${line%% *}"
      cidr="${line#* }"
      case "$op" in
        add)
          has_add=1
          if [[ -n "$gw" ]]; then
            printf 'route replace %s via %s dev %s table %s\n' "$cidr" "$gw" "$dev" "$table"
          else
            printf 'route replace %s dev %s table %s\n' "$cidr" "$dev" "$table"
          fi
          ;;
        del)
          if [[ -n "${excl[$cidr]:-}" ]]; then
            log "Маршрут оставлен (CIDR есть в другом exclude-файле): $cidr"
          else
            printf 'route del %s table %s\n' "$cidr" "$table"
          fi
          ;;
        *) die "Внутренняя ошибка: bad op '$op'" ;;
      esac
    done
  } > "$tmp"
  # del отсутствующего маршрута — нормально; WARNING только если были add.
  # Батч запускается РОВНО ОДИН раз: повторный прогон по удалённым маршрутам
  # с via-шлюзом стоит миллисекунды на строку в ядре.
  local rc=0
  sudo ip -force -batch "$tmp" >/dev/null 2>&1 || rc=1
  if (( rc != 0 && has_add )); then
    log "WARNING: часть маршрутов не применилась — проверьте 'ip route'"
  fi
  rm -f "$tmp"
  log "Применено изменений маршрутов: ${#ops[@]}"
}

# Массовое runtime-применение force-изменений (через туннель).
# stdin: строки "add CIDR" / "del CIDR".
apply_force_changes() {
  local ops=() line=""
  while IFS= read -r line; do
    [[ -n "$line" ]] && ops+=("$line")
  done
  ((${#ops[@]} > 0)) || return 0

  if ! tun_is_running; then
    log "Туннель не работает — маршруты подхватятся при следующем 'up'"
    return 0
  fi

  local rt tdev tip table
  rt="$(state_var TUN_DEV SERVER_TUN_IP POLICY_TABLE_DIRECT)"
  tdev="${rt%% *}"
  tip="$(awk '{print $2}' <<<"$rt")"
  table="$(awk '{print $3}' <<<"$rt")"
  if [[ "$UNAME_S" == "Darwin" ]]; then
    # macOS: diff не нужен — бэкенд пересобирает pf-таблицы из файлов политики.
    printf '%s\n' "${ops[@]}" | sudo -n "$ROOT_HELPER" backend-run apply-diff \
      && log "Применено изменений force-маршрутов: ${#ops[@]}" \
      || log "WARNING: apply-diff не удался"
    return 0
  fi
  if [[ -z "$tdev" || -z "$tip" || -z "$table" ]]; then
    log "Не прочитано состояние туннеля — маршруты подхватятся при следующем 'up'"
    return 0
  fi

  local tmp op cidr
  tmp="$(mktemp)" || return 1
  {
    for line in "${ops[@]}"; do
      op="${line%% *}"
      cidr="${line#* }"
      case "$op" in
        add) printf 'route replace %s via %s dev %s table %s\n' "$cidr" "$tip" "$tdev" "$table" ;;
        del) printf 'route del %s table %s\n' "$cidr" "$table" ;;
        *) die "Внутренняя ошибка: bad op '$op'" ;;
      esac
    done
  } > "$tmp"
  if ! sudo ip -force -batch "$tmp" >/dev/null 2>&1; then
    if [[ "${ops[0]%% *}" == "add" ]]; then
      log "WARNING: часть force-маршрутов не применилась — проверьте 'ip route'"
    fi
  fi
  rm -f "$tmp"
  log "Применено изменений force-маршрутов: ${#ops[@]}"
}

# Номер direct-таблицы: из state работающего туннеля (там значения клиента),
# иначе env/default. Маршруты include/exclude живут в этой таблице.
policy_table_direct_runtime() {
  local t=""
  t="$(state_var POLICY_TABLE_DIRECT)"
  [[ -n "$t" ]] && printf '%s' "$t" || printf '%s' "$POLICY_TABLE_DIRECT"
}

# Токены-источники из тела файла (по одному на строку).
file_tokens() {
  [[ -f "$1" ]] || return 0
  # Токены могут иметь inline-комментарий "AS9009 # пояснение" — отсекаем.
  sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" \
    | grep -E '^(AS[0-9]+|[A-Za-z]{2})$' || true
}

# Сырые строки токенов с комментариями ("AS9009 # пояснение") — для 'list'.
token_lines() {
  [[ -f "$1" ]] || return 0
  grep -E '^(AS[0-9]+|[A-Za-z]{2})([[:space:]]*#|$)' "$1" || true
}

# Разобрать аргументы fetch: токены... [-- комментарий].
# nameref: _tokens (массив), _comment (строка).
parse_tokens_comment() {
  local -n _tokens="$1"
  local -n _comment="$2"
  shift 2
  _tokens=()
  _comment=""
  local seen_ddash=0 arg=""
  for arg in "$@"; do
    if (( seen_ddash == 0 )) && [[ "$arg" == "--" ]]; then
      seen_ddash=1
      continue
    fi
    if (( seen_ddash == 1 )); then
      _comment+="${_comment:+ }$arg"
    else
      _tokens+=("$arg")
    fi
  done
}

# Шапка файла-токенов (AS / страны).
token_file_header() {
  cat <<'EOF'
# SSHTUN: источники автогенных префиксов. Формат: один токен на строку —
# AS9009 (автономная система) или ISO-код страны (ru, de, us), к нему можно
# добавить комментарий: "AS9009 # пояснение" (строки "# ..." и пустые —
# тоже комментарии). Префиксы скачиваются в ~/sshtun/generated/ командой
# 'sshtun refresh' или автоматически при 'up' (при недоступности сети
# используется последний кэш из generated/).
# Добавить/убрать: sshtun fetch-as AS9009 [-- комментарий] | fetch-as --remove AS9009
#                 sshtun fetch-country ru [-- комментарий] | fetch-country --remove ru
EOF
}

# Привязать/обновить комментарий для КОНКРЕТНЫХ токенов файла (остальные
# не трогаем). Реализовано как «убрать целевые строки, дописать с новым
# комментарием» — write_token_file ниже подхватит комментарии из файла.
set_token_comments() { # file comment token...
  local file="$1" comment="$2"; shift 2
  ((${#@} > 0)) || return 0
  local pat="" t="" tmp=""
  pat="$(printf '%s|' "$@")"; pat="${pat%|}"
  tmp="$(mktemp "$file.XXXXXX")" || die "mktemp failed"
  {
    [[ -f "$file" ]] && grep -vE "^(${pat})([[:space:]]|$)" "$file" || true
    for t in "$@"; do
      printf '%s # %s\n' "$t" "$comment"
    done
  } > "$tmp"
  mv -f "$tmp" "$file"
  restore_owner "$file"
}

# Полный набор строк управляемой шапки: текущий шаблон + исторические
# варианты — чтобы старые файлы самоочищались, а не копили «наследие»
# прошлых форматов как пользовательские комментарии.
managed_header_lines() {
  token_file_header
  cat <<'EOF'
# AS9009 (автономная система) или ISO-код страны (ru, de, us). Комментарии
# (#) и пустые строки допустимы. Префиксы скачиваются в ~/sshtun/generated/
# командой 'sshtun refresh' или автоматически при 'up' (при недоступности
# сети используется последний кэш из generated/).
# Добавить/убрать: sshtun fetch-as AS9009 | fetch-as --remove AS9009
#                 sshtun fetch-country ru | fetch-country --remove ru
EOF
}

# Перезаписать файл-токенов: свежая шапка + пользовательские комментарии
# + токены (отсортированные, уникальные) с сохранёнными inline-комментариями
# (токен -> комментарий читается из старого содержимого; новые — через
# set_token_comments ДО вызова). Старые управляемые шапки автоген-формата
# и инлайн-префиксы (legacy) выбрасываются. Если токенов не осталось и
# пользовательского содержимого тоже нет — файл удаляется.
write_token_file() { # file token...
  local file="$1"; shift
  local kept="" user_lines=""
  local -A cmt=()
  if [[ -f "$file" ]]; then
    # Существующие inline-комментарии: токен -> текст после '#'.
    local line="" tok="" c=""
    while IFS= read -r line; do
      tok="${line%%#*}"
      tok="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$tok")"
      [[ "$tok" =~ ^(AS[0-9]+|[A-Za-z]{2})$ ]] || continue
      c=""
      [[ "$line" == *#* ]] && c="$(sed -e 's/^[^#]*#[[:space:]]*//' <<<"$line")"
      cmt["$tok"]="$c"
    done < "$file"
    # Управляемую шапку вырезаем точным совпадением строк против живого
    # шаблона (паттерновый фильтр ломается при смене формата шапки —
    # старые строки шапки оседают как «пользовательские» и дублируются
    # при каждой перезаписи).
    kept="$(grep -vxF -f <(managed_header_lines) "$file" \
      | grep -vE '^# (SSHTUN:|командами:|Дописывать можно|они развернутся|Источники:|Данные:|Обновлено:|sshtun-managed-sources:)' \
      | grep -vE '^(AS[0-9]+|[A-Za-z]{2})([[:space:]]|$)' \
      | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$' || true)"
    user_lines="$(grep -vE '^[[:space:]]*(#|$)' <<<"$kept" || true)"
  fi
  if [[ $# -eq 0 && -z "$user_lines" ]]; then
    rm -f "$file"
    return 0
  fi
  local tmp t=""
  tmp="$(mktemp "$file.XXXXXX")" || die "mktemp failed"
  {
    token_file_header
    [[ -n "$kept" ]] && printf '%s\n' "$kept"
    if [[ $# -gt 0 ]]; then
      local sorted=""
      sorted="$(printf '%s\n' "$@" | sort -u)"
      while IFS= read -r t; do
        [[ -n "${cmt[$t]:-}" ]] && printf '%s # %s\n' "$t" "${cmt[$t]}" || printf '%s\n' "$t"
      done <<<"$sorted"
    fi
  } > "$tmp"
  mv -f "$tmp" "$file"
  restore_owner "$file"
}

# Legacy-миграция офлайн: в старом формате префиксы лежали инлайн в файле-токенов.
# Если generated-кэш ещё не создан — переносим инлайн-префиксы туда (без сети).
migrate_legacy_inline() { # src_token_file dst_generated
  local src="$1" dst="$2"
  [[ -f "$src" && ! -f "$dst" ]] || return 0
  local prefixes=""
  prefixes="$(list_entries "$src")" || prefixes=""
  [[ -n "$prefixes" ]] || return 0
  mkdir -p "$GENERATED_DIR"
  {
    echo "# SSHTUN: АВТОГЕНЕРАЦИЯ (мигрировано из старого формата офлайн; данные"
    echo "# могут быть устаревшими — выполните 'sshtun refresh' при появлении сети)."
    echo "# Источники: $(file_sources "$src")"
    echo "# Обновлено: $(ts_iso) (offline-migration)"
    printf '%s\n' "$prefixes"
  } > "$dst"
  restore_owner "$dst"
  log "Офлайн-миграция префиксов в $dst: $(printf '%s\n' "$prefixes" | grep -c .)"
}

# Подготовить generated/-кэш перед стартом туннеля.
# Источники ищутся и в теле (токены), и в legacy-шапке (sshtun-managed-sources)
# — старые файлы с инлайн-префиксами так перекачиваются при первом же 'up'.
# Токены есть: refresh (при неудаче — fallback на кэш, иначе legacy-миграция,
# иначе die). Источников нет: подхватим legacy-инлайн, если файл старого формата.
ensure_autogen() {
  local need=0
  local srcs=""
  srcs="$(file_sources "$AS_EXCLUDES")"
  [[ -n "$srcs" ]] && need=1
  srcs="$(file_sources "$COUNTRY_EXCLUDES")"
  [[ -n "$srcs" ]] && need=1
  if (( need == 0 )); then
    migrate_legacy_inline "$AS_EXCLUDES" "$AS_GENERATED"
    migrate_legacy_inline "$COUNTRY_EXCLUDES" "$COUNTRY_GENERATED"
    return 0
  fi
  if refresh_lists; then
    return 0
  fi
  log "WARNING: префиксы AS/стран не обновились (сеть недоступна?)"
  if [[ -f "$AS_GENERATED" || -f "$COUNTRY_GENERATED" ]]; then
    log "Использую кэш: $GENERATED_DIR"
    return 0
  fi
  migrate_legacy_inline "$AS_EXCLUDES" "$AS_GENERATED"
  migrate_legacy_inline "$COUNTRY_EXCLUDES" "$COUNTRY_GENERATED"
  if [[ -f "$AS_GENERATED" || -f "$COUNTRY_GENERATED" ]]; then
    log "Данные префиксов могут быть устаревшими — обновите: sshtun refresh"
    return 0
  fi
  die "Префиксы AS/стран недоступны: нет сети и нет кэша в $GENERATED_DIR"
}

# systemd-юнит sshtun.service установлен (LoadState=loaded) и systemd жив.
systemd_unit_available() {
  command -v systemctl >/dev/null 2>&1 || return 1
  [[ -d /run/systemd/system ]] || return 1
  [[ "$(systemctl show -p LoadState --value sshtun.service 2>/dev/null)" == "loaded" ]]
}

# Параметры, переданные через env: юнит имеет фиксированный Environment и их
# не увидит — такой запуск делаем напрямую, без маршрута через службу.
env_overrides_present() {
  local v
  for v in "$SERVER_HOST_FROM_ENV" "$SERVER_PORT_FROM_ENV" "$SSH_USER_FROM_ENV" \
           "$KEY_FILE_FROM_ENV" "$TUN_START_FROM_ENV" "$TUN_END_FROM_ENV" \
           "$MTU_FROM_ENV" "$TUN_NET_A_FROM_ENV" "$TUN_NET_B_FROM_ENV"; do
    [[ -n "$v" ]] && return 0
  done
  return 1
}

# Старт через службу: супервизор внутри юнита (up --foreground) видит смерть
# ssh и возвращает failure -> systemd перезапускает (Restart=always). Так
# туннель переживает сон ноутбука, обрыв сети и рестарт сервера.
start_via_systemd() {
  log "Поднимаю туннель службой sshtun (досмотр systemd)"
  sudo -n systemctl start sshtun
  # systemctl стартует юнит асинхронно: дожидаемся живого SSH_PID в state
  # (обычно ~10-15 с: autogen-списки + ssh-handshake) и показываем статус.
  local i
  for ((i = 0; i < 60; i++)); do
    if tun_is_running; then
      printf 'Профиль: %s\n' "$(profile_display)"
      sudo bash "$CLIENT_SCRIPT" status
      return 0
    fi
    sleep 2
  done
  die "Служба sshtun не подняла туннель за 120 с. Журнал: sudo journalctl -u sshtun -e --no-pager"
}

start_vpn() {
  local foreground=0 background=0
  [[ "${1:-}" == "--foreground" ]] && foreground=1
  [[ "${1:-}" == "--background" ]] && background=1
  [[ -n "$SERVER_HOST" ]] || die "SERVER_HOST не задан. Укажите адрес сервера:
  - через профиль: sshtun server add NAME HOST && sshtun server use NAME, или
  - в файле $SERVER_CONF (строка SERVER_HOST=your-server), или
  - через env: SERVER_HOST=your-server sshtun up"
  # Быстрый отказ, если туннель уже жив: клиент проверил бы это сам, но ПОСЛЕ
  # ensure_autogen (перекачка списков) — а при restart-цикле службы против
  # «сироты» каждая попытка тянула бы полный refresh. Здесь — до любых сетевых
  # операций.
  if tun_is_running; then
    die "Туннель уже работает (SSH_PID из state жив). Остановите сначала: sshtun down"
  fi
  check_client
  check_excludes
  check_key
  # Дефолт — ЧЕРЕЗ СЛУЖБУ. Иначе фоновый запуск без досмотра оставляет
  # «stale state» после сна/обрыва (некому перезапустить ssh). Фон без
  # досмотра — только явный 'up --background'.
  # На macOS служба — launchd (своя логика supervisor_*), systemd нет:
  # блок целиком только для Linux.
  if [[ "$UNAME_S" != "Darwin" ]] && (( ! background && ! foreground )); then
    if systemd_unit_available; then
      if env_overrides_present; then
        log "Параметры заданы через env — в systemd-юнит они не попадут;"
        log "поднимаю напрямую (без досмотра). Для досмотра настройте профиль: sshtun server add/use"
      else
        start_via_systemd
        return $?
      fi
    else
      log "WARNING: systemd-юнит sshtun.service не найден — поднимаю напрямую,"
      log "без досмотра (после сна/обрыва сам не переподнимется). Юнит ставит install_client.sh"
    fi
  fi
  # Токены AS/стран разворачиваем в префиксы (generated/) перед стартом.
  # Нет сети — используем кэш, если он есть (иначе мигрируем legacy инлайн).
  ensure_autogen
  log "Поднимаю туннель: $SSH_USER@$SERVER_HOST:$SERVER_PORT (пул tun$TUN_START..tun$TUN_END)"
  local args=(
    --host "$SERVER_HOST"
    --port "$SERVER_PORT"
    --user "$SSH_USER"
    --key "$KEY_FILE"
    --tun-start "$TUN_START"
    --tun-end "$TUN_END"
    --mtu "$MTU"
    --exclude-file "$BASE_EXCLUDES"
    --exclude-file "$CUSTOM_EXCLUDES"
  )
  [[ -f "$AS_GENERATED" ]] && args+=(--exclude-file "$AS_GENERATED")
  [[ -f "$COUNTRY_GENERATED" ]] && args+=(--exclude-file "$COUNTRY_GENERATED")
  [[ -f "$FORCE_INCLUDES" ]] && args+=(--route-file "$FORCE_INCLUDES")
  if (( foreground )); then
    # exec: процесс обёртки СТАНОВИТСЯ sudo -> клиент = main PID службы.
    # systemd при stop ждёт main: супервизор успевает дочистить маршруты,
    # а не получает SIGKILL посреди cleanup (было: t201 чист, t200 — нет).
    # Падение любого звена всё равно видно systemd как смерть main -> рестарт
    # (Restart=always), ручной down идёт через 'systemctl stop' (маркер
    # SUPERVISED=1 в state). TUN_NET_* пробрасываем через env: sudo по
    # умолчанию сбрасывает окружение, а клиент считает IP-пару из него.
    args+=(--foreground)
    if [[ "$UNAME_S" == "Darwin" ]]; then
      # env TUN_NET_* проходят через Defaults env_keep (sudoers) в хелпер.
      exec env TUN_NET_A="$TUN_NET_A" TUN_NET_B="$TUN_NET_B" \
        sudo -n "$ROOT_HELPER" backend-run start "${args[@]}"
    fi
    exec sudo env TUN_NET_A="$TUN_NET_A" TUN_NET_B="$TUN_NET_B" \
      bash "$CLIENT_SCRIPT" start "${args[@]}"
  fi
  if [[ "$UNAME_S" == "Darwin" ]]; then
    env TUN_NET_A="$TUN_NET_A" TUN_NET_B="$TUN_NET_B" \
      sudo -n "$ROOT_HELPER" backend-run start "${args[@]}"
    return $?
  fi
  sudo env TUN_NET_A="$TUN_NET_A" TUN_NET_B="$TUN_NET_B" \
    bash "$CLIENT_SCRIPT" start "${args[@]}"
}

# Маркер SUPERVISED из state работающего туннеля ("1" — под досмотром systemd).
supervised_marker() {
  state_var SUPERVISED
}

# Остановка туннеля, поднятого службой досмотра (systemd / launchd).
supervisor_stop() {
  if [[ "$UNAME_S" == "Darwin" ]]; then
    log "Туннель под досмотром launchd — останавливаю: bootout $MACOS_SERVICE"
    sudo -n "$ROOT_HELPER" service-stop
  else
    log "Туннель под досмотром systemd — останавливаю службу: systemctl stop sshtun"
    sudo -n systemctl stop sshtun
  fi
}

supervisor_restart() {
  if [[ "$UNAME_S" == "Darwin" ]]; then
    log "Туннель под досмотром launchd — перезапускаю: kickstart -k $MACOS_SERVICE"
    sudo -n "$ROOT_HELPER" service-restart
  else
    log "Туннель под досмотром systemd — перезапускаю службу: systemctl restart sshtun"
    sudo -n systemctl restart sshtun
  fi
}

stop_vpn() {
  check_client
  # Туннель под досмотром службы (маркер SUPERVISED=1 в state): останавливаем
  # ЧЕРЕЗ неё — иначе политика перезапуска вернула бы его после down.
  if [[ "$(supervised_marker)" == "1" ]]; then
    supervisor_stop
    return
  fi
  client_cmd stop
}

restart_vpn() {
  if [[ "$(supervised_marker)" == "1" ]]; then
    supervisor_restart
    return
  fi
  stop_vpn || true
  start_vpn "$@"
}

add_excludes() {
  local cidrs=() comment=""
  parse_cidrs_comment cidrs comment "$@"
  ((${#cidrs[@]} >= 1)) || die "Укажите хотя бы одну сеть/адрес: $0 exclude add 203.0.113.0/24"
  mkdir -p "$EXCLUDES_DIR"
  touch "$CUSTOM_EXCLUDES"

  local cidr="" adds=() tmp=""
  for cidr in "${cidrs[@]}"; do
    cidr="$(normalize_cidr "$cidr")"
    if cidr_line_exists "$CUSTOM_EXCLUDES" "$cidr"; then
      if [[ -n "$comment" ]]; then
        # обновить комментарий: переписать строку и перенести в конец
        tmp="$(mktemp)"
        remove_cidr_lines "$CUSTOM_EXCLUDES" "$cidr" > "$tmp"
        mv -f "$tmp" "$CUSTOM_EXCLUDES"
        printf '%s # %s\n' "$cidr" "$comment" >> "$CUSTOM_EXCLUDES"
        log "Комментарий обновлён: $cidr # $comment"
      else
        log "Уже есть в списке: $cidr"
      fi
    else
      if [[ -n "$comment" ]]; then
        printf '%s # %s\n' "$cidr" "$comment" >> "$CUSTOM_EXCLUDES"
        log "Записано в $CUSTOM_EXCLUDES: $cidr # $comment"
      else
        printf '%s\n' "$cidr" >> "$CUSTOM_EXCLUDES"
        log "Записано в $CUSTOM_EXCLUDES: $cidr"
      fi
      adds+=("add $cidr")
    fi
  done
  ((${#adds[@]})) && printf '%s\n' "${adds[@]}" | apply_direct_changes
}

del_excludes() {
  local cidrs=() comment=""
  parse_cidrs_comment cidrs comment "$@"
  ((${#cidrs[@]} >= 1)) || die "Укажите хотя бы одну сеть/адрес: $0 exclude del 203.0.113.0/24"
  mkdir -p "$EXCLUDES_DIR"
  touch "$CUSTOM_EXCLUDES"

  local cidr="" dels=() tmp=""
  for cidr in "${cidrs[@]}"; do
    cidr="$(normalize_cidr "$cidr")"
    if cidr_line_exists "$CUSTOM_EXCLUDES" "$cidr"; then
      tmp="$(mktemp)"
      remove_cidr_lines "$CUSTOM_EXCLUDES" "$cidr" > "$tmp"
      mv -f "$tmp" "$CUSTOM_EXCLUDES"
      log "Удалено из $CUSTOM_EXCLUDES: $cidr"
      dels+=("del $cidr")
    else
      log "Нет в $CUSTOM_EXCLUDES: $cidr"
    fi
  done
  ((${#dels[@]})) && printf '%s\n' "${dels[@]}" | apply_direct_changes
}

force_add() {
  local cidrs=() comment=""
  parse_cidrs_comment cidrs comment "$@"
  ((${#cidrs[@]} >= 1)) || die "Укажите хотя бы одну сеть/адрес: $0 include add 203.0.113.0/24"
  mkdir -p "$EXCLUDES_DIR"
  touch "$FORCE_INCLUDES"

  local cidr="" adds=() tmp=""
  for cidr in "${cidrs[@]}"; do
    cidr="$(normalize_cidr "$cidr")"
    if cidr_line_exists "$FORCE_INCLUDES" "$cidr"; then
      if [[ -n "$comment" ]]; then
        tmp="$(mktemp)"
        remove_cidr_lines "$FORCE_INCLUDES" "$cidr" > "$tmp"
        mv -f "$tmp" "$FORCE_INCLUDES"
        printf '%s # %s\n' "$cidr" "$comment" >> "$FORCE_INCLUDES"
        log "Комментарий обновлён: $cidr # $comment"
      else
        log "Уже есть в include-списке: $cidr"
      fi
    else
      if [[ -n "$comment" ]]; then
        printf '%s # %s\n' "$cidr" "$comment" >> "$FORCE_INCLUDES"
        log "Записано в $FORCE_INCLUDES: $cidr # $comment"
      else
        printf '%s\n' "$cidr" >> "$FORCE_INCLUDES"
        log "Записано в $FORCE_INCLUDES: $cidr"
      fi
      adds+=("add $cidr")
    fi
  done
  ((${#adds[@]})) && printf '%s\n' "${adds[@]}" | apply_force_changes
}

force_del() {
  local cidrs=() comment=""
  parse_cidrs_comment cidrs comment "$@"
  ((${#cidrs[@]} >= 1)) || die "Укажите хотя бы одну сеть/адрес: $0 include del 203.0.113.0/24"
  mkdir -p "$EXCLUDES_DIR"
  touch "$FORCE_INCLUDES"

  local cidr="" dels=() tmp=""
  for cidr in "${cidrs[@]}"; do
    cidr="$(normalize_cidr "$cidr")"
    if cidr_line_exists "$FORCE_INCLUDES" "$cidr"; then
      tmp="$(mktemp)"
      remove_cidr_lines "$FORCE_INCLUDES" "$cidr" > "$tmp"
      mv -f "$tmp" "$FORCE_INCLUDES"
      log "Удалено из $FORCE_INCLUDES: $cidr"
      dels+=("del $cidr")
    else
      log "Нет в $FORCE_INCLUDES: $cidr"
    fi
  done
  ((${#dels[@]})) && printf '%s\n' "${dels[@]}" | apply_force_changes
}

# --- резолвинг источников данных ---

# Фактически анонсируемые префиксы AS из RIPEstat (только IPv4, по одному на строку).
ripestat_prefixes() {
  local asn="$1" json=""
  json="$(curl -sfL --retry 2 --max-time 90 \
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=${asn}")" \
    || return 1
  if command -v jq >/dev/null 2>&1; then
    jq -r '.data.prefixes[].prefix' <<<"$json"
  else
    python3 -c 'import json,sys
d = json.load(sys.stdin)
print("\n".join(p["prefix"] for p in d["data"]["prefixes"]))' <<<"$json"
  fi | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$'
}

# Префиксы AS через bgpq4 (IRR-источники — могут содержать устаревшие записи).
irr_prefixes() {
  command -v bgpq4 >/dev/null 2>&1 || die "bgpq4 не установлен: sudo apt install bgpq4 (или уберите --irr)"
  bgpq4 -4A -F '%n/%l\n' "$1" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$'
}

# Префиксы страны из ipdeny.com (агрегированные, обновляются ежедневно).
ipdeny_prefixes() {
  local cc="$1"
  curl -sfL --retry 2 --max-time 90 \
    "https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone" \
    | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$'
}

# Источники файла: шапка (# sshtun-managed-sources:) + вручную дописанные
# в тело токены (ASnnnn или ISO-код страны), через пробел. Печатает одну строку.
file_sources() {
  local file="$1"
  {
    managed_sources "$file"
    file_tokens "$file"
  } | tr '\n' ' '
}

# Источники файла ПЛЮС новые аргументы (уникально). По одному на строку.
merge_sources() {
  local file="$1"; shift
  local -A seen=()
  local s="" line=""
  local -a old=()
  line="$(file_sources "$file")"
  IFS=' ' read -r -a old <<<"$line"
  for s in "${old[@]}"; do
    [[ -n "$s" ]] || continue
    if [[ -z "${seen[$s]:-}" ]]; then seen[$s]=1; printf '%s\n' "$s"; fi
  done
  for s in "$@"; do
    if [[ -z "${seen[$s]:-}" ]]; then seen[$s]=1; printf '%s\n' "$s"; fi
  done
}

# Склеить элементы массива через пробел (независимо от IFS).
join_spaced() {
  local out="" x=""
  for x in "$@"; do out+="$x "; done
  printf '%s' "${out% }"
}

# Источники файла МИНУС указанные (для --remove). По одному на строку.
# Вручную дописанные токены из тела учитываются: удалённый токен не
# воскреснет при следующем refresh.
subtract_sources() {
  local file="$1"; shift
  local -A rm=()
  local s="" line=""
  local -a old=()
  for s in "$@"; do rm[$s]=1; done
  line="$(file_sources "$file")"
  IFS=' ' read -r -a old <<<"$line"
  for s in "${old[@]}"; do
    [[ -n "$s" ]] || continue
    [[ -n "${rm[$s]:-}" ]] && continue
    printf '%s\n' "$s"
  done
}

# Перезаписать автогенный generated-файл: шапка + отсортированные уникальные
# префиксы. $1 — файл, $2 — читаемый список источников (через пробел), $3 — источник данных,
# stdin — префиксы. Старое содержимое сохраняется во временный файл и печатается
# в stdout-потоке как OLD_ENTRIES_FILE=... для последующего diff.
write_managed_file() {
  local file="$1" sources="$2" datasource="$3"
  local tmp
  tmp="$(mktemp)" || die "mktemp failed"
  mkdir -p "$(dirname "$file")"
  restore_owner "$(dirname "$file")"
  {
    echo "# SSHTUN: АВТОГЕНЕРАЦИЯ. Не править префиксы вручную — файл перезаписывается"
    echo "# командами: fetch-as / fetch-country / refresh (в т.ч. автоматически при up)."
    echo "# Источники-ТОКЕНЫ лежат отдельно (~/sshtun/excludes-as.txt, excludes-country.txt)."
    echo "# Источники: $sources"
    echo "# Данные: $datasource"
    echo "# Обновлено: $(ts_iso)"
    echo "# sshtun-managed-sources: $sources"
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -u
  } > "$tmp"
  local old
  old="$(mktemp)" || die "mktemp failed"
  list_entries "$file" > "$old" 2>/dev/null || true
  mv -f "$tmp" "$file"
  restore_owner "$file"
  printf '%s' "$old"
}

# diff старого и нового содержимого -> строки "add CIDR" / "del CIDR" в stdout.
diff_entries() { # old_file new_file
  comm -13 "$1" "$2" | sed 's/^/add /'
  comm -23 "$1" "$2" | sed 's/^/del /'
}

fetch_as() {
  local use_irr=0 comment="" i=0 a="" next=""
  local -a asns=() rm_asns=() args=()
  parse_tokens_comment args comment "$@"
  for (( i=0; i<${#args[@]}; i++ )); do
    a="${args[$i]}"
    case "$a" in
      --irr) use_irr=1 ;;
      --remove)
         next="${args[$((i+1))]:-}"
         [[ "$next" =~ ^(AS)?[0-9]+$ ]] || die "Не похоже на номер AS: ${next:-(пусто)}"
         rm_asns+=("AS${next#AS}") ;;
      *) [[ "$a" =~ ^(AS)?[0-9]+$ ]] || die "Не похоже на номер AS: $a (нужно вида AS9009)"
         asns+=("AS${a#AS}") ;;
    esac
  done
  ((${#asns[@]} >= 1 || ${#rm_asns[@]} >= 1)) || die "Укажите хотя бы одну AS: $0 fetch-as AS9009"

  mkdir -p "$EXCLUDES_DIR"
  local -a src_array=()
  if ((${#rm_asns[@]} > 0)); then
    mapfile -t src_array < <(subtract_sources "$AS_EXCLUDES" "${rm_asns[@]}")
    log "Убираю AS: $(join_spaced "${rm_asns[@]}")"
  else
    mapfile -t src_array < <(merge_sources "$AS_EXCLUDES" "${asns[@]}")
    [[ -n "$comment" ]] && log "Комментарий к AS: $comment"
  fi

  # Комментарий привязываем ТОЛЬКО к токенам текущего вызова (не ко всем
  # источникам файла), затем перезаписываем файл (токены + комментарии);
  # префиксы — в generated/.
  if [[ -n "$comment" && ${#asns[@]} -gt 0 ]]; then
    set_token_comments "$AS_EXCLUDES" "$comment" "${asns[@]}"
  fi
  write_token_file "$AS_EXCLUDES" "${src_array[@]}"

  if ((${#src_array[@]} == 0)); then
    # Источников не осталось: generated-файл удаляем, маршруты снимаются через diff.
    local old
    old="$(mktemp)"
    list_entries "$AS_GENERATED" > "$old" 2>/dev/null || true
    if [[ -f "$AS_GENERATED" ]]; then
      rm -f "$AS_GENERATED"
      log "Источников не осталось — generated-файл удалён: $AS_GENERATED"
    else
      log "Источников не осталось — файла и не было"
    fi
    local empty
    empty="$(mktemp)"
    : > "$empty"
    diff_entries "$old" "$empty" | apply_direct_changes
    rm -f "$old" "$empty"
    return 0
  fi

  local sources
  sources="$(join_spaced "${src_array[@]}")"
  log "Резолвлю префиксы: $sources (источник: $([[ $use_irr -eq 1 ]] && echo bgpq4/IRR || echo RIPEstat))"

  local combined_file prefixes="" asn=""
  combined_file="$(mktemp)" || die "mktemp failed"
  : > "$combined_file"
  for asn in "${src_array[@]}"; do
    if [[ $use_irr -eq 1 ]]; then
      prefixes="$(irr_prefixes "$asn")" || { log "ERROR: bgpq4 не ответил для $asn"; rm -f "$combined_file"; return 1; }
    else
      prefixes="$(ripestat_prefixes "$asn")" || { log "ERROR: RIPEstat не ответил для $asn (повторите или используйте --irr)"; rm -f "$combined_file"; return 1; }
    fi
    printf '%s\n' "$prefixes" >> "$combined_file"
    log "$asn: $(printf '%s\n' "$prefixes" | grep -c .) префиксов"
  done

  local datasource="RIPEstat (фактически анонсируемые префиксы)"
  [[ $use_irr -eq 1 ]] && datasource="bgpq4 / IRR (может содержать устаревшие записи)"
  local old
  old="$(write_managed_file "$AS_GENERATED" "$sources" "$datasource" < "$combined_file")"
  rm -f "$combined_file"

  local new
  new="$(mktemp)"
  list_entries "$AS_GENERATED" > "$new"
  log "Записано в $AS_GENERATED: $(grep -c . "$new" || true) префиксов"
  diff_entries "$old" "$new" | apply_direct_changes
  rm -f "$old" "$new"
}

fetch_country() {
  local comment="" i=0 a="" next=""
  local -a ccs=() rm_ccs=() args=()
  parse_tokens_comment args comment "$@"
  for (( i=0; i<${#args[@]}; i++ )); do
    a="${args[$i]}"
    case "$a" in
      --remove)
         next="${args[$((i+1))]:-}"
         [[ "$next" =~ ^[A-Za-z]{2}$ ]] || die "Не похоже на код страны: ${next:-(пусто)}"
         rm_ccs+=("$(tr 'A-Z' 'a-z' <<<"$next")") ;;
      *) [[ "$a" =~ ^[A-Za-z]{2}$ ]] || die "Не похоже на код страны: $a (нужно вида ru, de, us)"
         ccs+=("$(tr 'A-Z' 'a-z' <<<"$a")") ;;
    esac
  done
  ((${#ccs[@]} >= 1 || ${#rm_ccs[@]} >= 1)) || die "Укажите хотя бы одну страну: $0 fetch-country ru"

  local combined_file="" prefixes="" cc=""
  mkdir -p "$EXCLUDES_DIR"

  local -a src_array=()
  if ((${#rm_ccs[@]} > 0)); then
    mapfile -t src_array < <(subtract_sources "$COUNTRY_EXCLUDES" "${rm_ccs[@]}")
    log "Убираю страны: $(join_spaced "${rm_ccs[@]}")"
  else
    mapfile -t src_array < <(merge_sources "$COUNTRY_EXCLUDES" "${ccs[@]}")
    [[ -n "$comment" ]] && log "Комментарий к странам: $comment"
  fi

  # Комментарий привязываем только к странам текущего вызова; префиксы — в generated/.
  if [[ -n "$comment" && ${#ccs[@]} -gt 0 ]]; then
    set_token_comments "$COUNTRY_EXCLUDES" "$comment" "${ccs[@]}"
  fi
  write_token_file "$COUNTRY_EXCLUDES" "${src_array[@]}"

  if ((${#src_array[@]} == 0)); then
    local old
    old="$(mktemp)"
    list_entries "$COUNTRY_GENERATED" > "$old" 2>/dev/null || true
    if [[ -f "$COUNTRY_GENERATED" ]]; then
      rm -f "$COUNTRY_GENERATED"
      log "Источников не осталось — generated-файл удалён: $COUNTRY_GENERATED"
    else
      log "Источников не осталось — файла и не было"
    fi
    local empty
    empty="$(mktemp)"
    : > "$empty"
    diff_entries "$old" "$empty" | apply_direct_changes
    rm -f "$old" "$empty"
    return 0
  fi

  local sources
  sources="$(join_spaced "${src_array[@]}")"
  log "Скачиваю префиксы стран: $sources (ipdeny.com)"

  combined_file="$(mktemp)" || die "mktemp failed"
  : > "$combined_file"
  for cc in "${src_array[@]}"; do
    prefixes="$(ipdeny_prefixes "$cc")" || { log "ERROR: ipdeny.com не ответил для $cc"; rm -f "$combined_file"; return 1; }
    printf '%s\n' "$prefixes" >> "$combined_file"
    log "$cc: $(printf '%s\n' "$prefixes" | grep -c .) префиксов"
  done

  local old
  old="$(write_managed_file "$COUNTRY_GENERATED" "$sources" "ipdeny.com country zones" < "$combined_file")"
  rm -f "$combined_file"

  local new
  new="$(mktemp)"
  list_entries "$COUNTRY_GENERATED" > "$new"
  log "Записано в $COUNTRY_GENERATED: $(grep -c . "$new" || true) префиксов"
  diff_entries "$old" "$new" | apply_direct_changes
  rm -f "$old" "$new"
}

refresh_lists() {
  log "Обновляю автогенные списки"
  # Источники берутся из файлов-токенов (шапка legacy + токены в теле)
  # и распределяются по форме: ASnnnn -> fetch_as, иначе -> fetch_country.
  local all_sources="" as_sources="" cc_sources="" tok=""
  all_sources="$(file_sources "$AS_EXCLUDES") $(file_sources "$COUNTRY_EXCLUDES")"
  local -a toks=()
  local -A seen=()
  IFS=' ' read -r -a toks <<<"$all_sources"
  for tok in "${toks[@]}"; do
    [[ -n "$tok" ]] || continue
    [[ -n "${seen[$tok]:-}" ]] && continue
    seen[$tok]=1
    if [[ "$tok" =~ ^AS[0-9]+$ ]]; then
      as_sources+="$tok "
    else
      cc_sources+="$tok "
    fi
  done

  local rc=0
  if [[ -n "$as_sources" ]]; then
    local -a arr=()
    IFS=' ' read -r -a arr <<<"$as_sources"
    log "AS-список обновится из RIPEstat (исходный источник данных не запоминается)"
    fetch_as "${arr[@]}" || rc=1
  else
    log "Нет автогенного AS-списка — пропускаю"
  fi
  if [[ -n "$cc_sources" ]]; then
    local -a arr=()
    IFS=' ' read -r -a arr <<<"$cc_sources"
    fetch_country "${arr[@]}" || rc=1
  else
    log "Нет автогенного country-списка — пропускаю"
  fi
  return "$rc"
}

# Сырые содержательные строки файла (без чистых комментариев и пустых) —
# для показа в list вместе с inline-комментариями "CIDR # текст".
show_raw_entries() {
  [[ -f "$1" ]] || return 0
  sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$1"
}

list_policy() {
  local f="" title="" n=0 t=0
  echo "=== INCLUDE (принудительно В ТУННЕЛЬ; на равных префиксах побеждает exclude-ы):"
  echo "    добавить: sshtun include add CIDR...    убрать: sshtun include del CIDR..."
  echo "    файл: $FORCE_INCLUDES"
  if [[ -f "$FORCE_INCLUDES" ]]; then
    n="$(list_entries "$FORCE_INCLUDES" | grep -c . || true)"
    if (( n > 0 )); then
      show_raw_entries "$FORCE_INCLUDES" | sed 's/^/      /'
    else
      echo "      (пусто)"
    fi
  else
    echo "      (пусто — файла нет, создастся первой командой include add)"
  fi
  echo
  echo "=== EXCLUDE (напрямую, мимо туннеля):"
  echo "    свои сети:  sshtun exclude add CIDR...   (или строки CIDR в excludes-custom.txt)"
  echo "    целые AS:   sshtun fetch-as AS9009       (или токен AS9009 в excludes-as.txt)"
  echo "    страны:     sshtun fetch-country ru      (или токен ru в excludes-country.txt)"
  echo "    префиксы AS/стран скачиваются в $GENERATED_DIR/"
  echo
  for f in "$BASE_EXCLUDES" "$CUSTOM_EXCLUDES" "$AS_EXCLUDES" "$COUNTRY_EXCLUDES"; do
    case "$f" in
      "$BASE_EXCLUDES") title="базовые" ;;
      "$CUSTOM_EXCLUDES") title="пользовательские" ;;
      "$AS_EXCLUDES") title="источники AS" ;;
      "$COUNTRY_EXCLUDES") title="источники стран" ;;
    esac
    if [[ -f "$f" ]]; then
      n="$(list_entries "$f" | grep -c . || true)"
      t="$(file_tokens "$f" | grep -c . || true)"
      printf '    %-18s %6s токен(ов)   %s\n' "$title" "$t" "$f"
      if (( t > 0 )); then
        token_lines "$f" | sed 's/^/      /'
      fi
      if [[ "$f" == "$AS_EXCLUDES" || "$f" == "$COUNTRY_EXCLUDES" ]] && (( n > 0 )); then
        printf '    %-18s %6s префиксов (legacy-инлайн, ещё не мигрировано)\n' "" "$n"
      elif (( n > 0 && n <= 50 )); then
        show_raw_entries "$f" | sed 's/^/      /'
      fi
    else
      printf '    %-18s %6s            %s\n' "$title" "—" "$f (нет файла)"
    fi
  done
  for f in "$AS_GENERATED" "$COUNTRY_GENERATED"; do
    case "$f" in
      "$AS_GENERATED") title="автоген AS" ;;
      "$COUNTRY_GENERATED") title="автоген страны" ;;
    esac
    if [[ -f "$f" ]]; then
      n="$(list_entries "$f" | grep -c . || true)"
      printf '    %-18s %6s префиксов  %s\n' "$title" "$n" "$f"
    else
      printf '    %-18s %6s            %s\n' "$title" "—" "$f (создаётся: fetch/refresh/up)"
    fi
  done
  echo
  echo "Приоритет: более длинный префикс побеждает всегда (LPM); на равных — include."
}

legacy_hint() {
  log "Подсказка: синтаксис устарел — используйте: sshtun $1"
}

# Активный профиль: применить server.conf (env побеждает файл).
# До dispatch — чтобы ВСЕ команды (up/status/list/...) видели параметры
# сервера из активного профиля, а не только 'server use'.
reload_server_conf

cmd="${1:-}"
case "$cmd" in
  up|start)        shift; start_vpn "$@" ;;
  down|stop)       shift; stop_vpn "$@" ;;
  restart)         shift; restart_vpn "$@" ;;
  status)          shift; check_client; printf 'Профиль: %s\n' "$(profile_display)"; client_cmd status "$@" ;;
  doctor)          shift; check_client; client_cmd doctor "$@" ;;
  cleanup)         shift; check_client; client_cmd cleanup "$@" ;;
  exclude)
    shift
    [[ $# -ge 1 ]] || die "Укажите подкоманду: $0 exclude add|del CIDR..."
    sub="${1:-}"; shift
    case "$sub" in
      add|+)  add_excludes "$@" ;;
      del|-)  del_excludes "$@" ;;
      *) die "Неизвестная подкоманда: exclude $sub (нужно add|del)" ;;
    esac ;;
  include)
    shift
    [[ $# -ge 1 ]] || die "Укажите подкоманду: $0 include add|del CIDR..."
    sub="${1:-}"; shift
    case "$sub" in
      add|+)  force_add "$@" ;;
      del|-)  force_del "$@" ;;
      *) die "Неизвестная подкоманда: include $sub (нужно add|del)" ;;
    esac ;;
  add)             shift; legacy_hint "exclude add CIDR..."; add_excludes "$@" ;;
  del)             shift; legacy_hint "exclude del CIDR..."; del_excludes "$@" ;;
  force-add)       shift; legacy_hint "include add CIDR..."; force_add "$@" ;;
  force-del)       shift; legacy_hint "include del CIDR..."; force_del "$@" ;;
  fetch-as)        shift; fetch_as "$@" ;;
  fetch-country)   shift; fetch_country "$@" ;;
  refresh)         shift; refresh_lists "$@" ;;
  list)            shift; list_policy "$@" ;;
  server)
    shift
    [[ $# -ge 1 ]] || die "Укажите подкоманду: $0 server list|add|use|del ..."
    sub="${1:-}"; shift
    case "$sub" in
      list|ls)  server_list "$@" ;;
      add)      server_add "$@" ;;
      use)      server_use "$@" ;;
      del|rm)   server_del "$@" ;;
      rename|mv) server_rename "$@" ;;
      *) die "Неизвестная подкоманда: server $sub (нужно list|add|use|del|rename)" ;;
    esac ;;
  -h|--help|help|"") usage ;;
  *)
    # Сокращение: 'sshtun <имя-профиля>' = 'sshtun server use <имя>'.
    # Срабатывает только для существующего профиля; имена, совпадающие
    # с командами выше (up/down/...), недоступны как сокращение.
    if [[ -f "$SERVERS_DIR/$cmd.conf" ]]; then
      server_use "$cmd"
    else
      die "Неизвестная команда: $cmd (см. $0 --help)"
    fi ;;
esac
