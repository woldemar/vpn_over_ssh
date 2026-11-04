#!/usr/bin/env bash
# ==========================================================
# sshtun-root — ЕДИНСТВЕННАЯ root-команда, разрешённая в sudoers
# (/etc/sudoers.d/sshtun: NOPASSWD только для этого файла).
#
# Обёртка sshtun на macOS не вызывает «sudo bash …» напрямую (это было бы
# эквивалентно NOPASSWD: ALL), а идёт через этот хелпер:
#   backend-run [args]     -> запуск sshtun_macos.sh от root
#                             (env TUN_NET_A/TUN_NET_B проходят через
#                             Defaults env_keep в sudoers)
#   state-var VAR...       -> чтение переменных из /var/run/sshtun/state
#   service-stop           -> launchctl bootout/stop (досмотр службы)
#   service-start          -> launchctl bootout+bootstrap (поднять/перечитать
#                             службу; KeepAlive сам стартует туннель)
#   service-restart        -> launchctl kickstart -k
#
# Файл принадлежит root и лежит в root-owned каталоге /opt/sshtun_client:
# без sudo его не изменить, значит NOPASSWD-окно не расширяется.
# ==========================================================
set -euo pipefail
IFS=$'\n\t'

# shellcheck disable=SC1091
[[ -f "$(dirname -- "$0")/env.conf" ]] && source "$(dirname -- "$0")/env.conf"
BASH_BIN="${BASH_BIN:-bash}"
# Бэкенд живёт в репозитории (env.conf: SSHTUN_BACKEND) — обновляется git pull
# без root; /opt-копия — fallback для случая без репозитория.
BACKEND="${SSHTUN_BACKEND:-$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P)/sshtun_macos.sh}"
STATE_FILE="/var/run/sshtun/state"
SERVICE_LABEL="com.sshtun.client"

case "${1:-}" in
  backend-run)
    shift
    export TUN_NET_A="${TUN_NET_A:-10}"
    export TUN_NET_B="${TUN_NET_B:-250}"
    exec "$BASH_BIN" "$BACKEND" "$@"
    ;;
  state-var)
    shift
    [[ -f "$STATE_FILE" ]] || exit 0
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    while (($#)); do
      eval "printf '%s' \"\${$1:-}\""
      shift
      (($# > 0)) && printf ' '
    done
    ;;
  service-stop)
    exec launchctl bootout "system/$SERVICE_LABEL" 2>/dev/null \
      || exec launchctl stop "$SERVICE_LABEL"
    ;;
  service-start)
    # Загрузить (или перечитать после правки plist): bootout + bootstrap.
    # KeepAlive в plist сам поднимет туннель сразу после bootstrap.
    PLIST="/Library/LaunchDaemons/$SERVICE_LABEL.plist"
    [[ -f "$PLIST" ]] || { echo "нет $PLIST — запустите install_macos.sh" >&2; exit 1; }
    launchctl bootout "system/$SERVICE_LABEL" 2>/dev/null || true
    exec launchctl bootstrap "system" "$PLIST"
    ;;
  service-restart)
    exec launchctl kickstart -k "system/$SERVICE_LABEL"
    ;;
  *)
    echo "usage: sshtun-root backend-run|state-var|service-stop|service-restart ..." >&2
    exit 2
    ;;
esac
