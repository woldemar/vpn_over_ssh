#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ==========================================================
# install_macos.sh — установка macOS-клиента vpn_over_ssh
#
# Что делает:
#   - проверяет зависимости (bash >= 4.3 через brew, python3, ssh, pfctl)
#   - копирует обёртку + macOS-бэкенд в /opt/sshtun_client (атомарно: tmp+mv)
#   - symlink /usr/local/bin/sshtun
#   - сеет ~/sshtun из examples/ (существующие файлы не трогает)
#   - ставит pf-анкор: /etc/pf.anchors/com.sshtun + строка anchor в /etc/pf.conf
#   - ставит LaunchDaemon /Library/LaunchDaemons/com.sshtun.client.plist
#     (ВЫКЛЮЧЕН по умолчанию; включение — launchctl bootstrap, см. HOWTO-macos)
#
# Использование:
#   sudo bash install_macos.sh [install|uninstall|reinstall]
# ==========================================================

INSTALL_DIR="${INSTALL_DIR:-/opt/sshtun_client}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
LINK_NAME="${LINK_NAME:-sshtun}"
SERVICE_LABEL="com.sshtun.client"
PLIST_PATH="/Library/LaunchDaemons/$SERVICE_LABEL.plist"
PF_ANCHOR_FILE="/etc/pf.anchors/com.sshtun"
PF_CONF="/etc/pf.conf"
LOG_FILE="/var/log/sshtun.log"
TEMPLATES=(excludes.txt excludes-custom.txt excludes-as.txt excludes-country.txt server.conf)

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

log(){ echo "[install] $*"; }
die(){ echo "[install][ERROR] $*" >&2; exit 1; }

# --- зависимости ------------------------------------------------------------
check_deps() {
  # Системный bash macOS — 3.2 (без nameref/assoc-arrays, обёртка их юзает).
  if ((${BASH_VERSINFO[0]} < 4 || (${BASH_VERSINFO[0]} == 4 && ${BASH_VERSINFO[1]} < 3))); then
    die "Нужен bash >= 4.3, а запущен $BASH_VERSION. Установите: brew install bash"
  fi
  local brew_bash=""
  brew_bash="$(command -v bash || true)"
  case "$brew_bash" in
    /bin/bash|/usr/bin/bash|"") ;;
    *) log "bash: $brew_bash ($BASH_VERSION)" ;;
  esac
  local c=""
  for c in ssh python3 ifconfig networksetup pfctl route dig; do
    command -v "$c" >/dev/null 2>&1 || die "Нет утилиты: $c (python3 — Xcode CLT: xcode-select --install)"
  done
  log "Dependencies OK"
}

# --- файлы ------------------------------------------------------------------
install_files() {
  mkdir -p "$INSTALL_DIR"
  local f="" tmp=""
  for f in sshtun_full.sh sshtun_macos.sh; do
    [[ -f "$REPO_DIR/$f" ]] || die "Нет файла в репозитории: $REPO_DIR/$f"
    tmp="$(mktemp "$INSTALL_DIR/.$f.XXXXXX")"
    install -m 0755 "$REPO_DIR/$f" "$tmp"
    mv -f "$tmp" "$INSTALL_DIR/$f"   # атомарно: работающий процесс не словит битый скрипт
    log "Установлен: $INSTALL_DIR/$f"
  done
  ln -sfn "$INSTALL_DIR/sshtun_full.sh" "$BIN_DIR/$LINK_NAME"
  log "Ссылка: $BIN_DIR/$LINK_NAME -> $INSTALL_DIR/sshtun_full.sh"
}

seed_data() {
  local u="${SUDO_USER:-$USER}"
  local home=""
  home="$(eval echo "~$u")"
  [[ -d "$home" ]] || { log "Домашний каталог $u не найден — seed пропущен"; return 0; }
  local dir="$home/sshtun" f=""
  mkdir -p "$dir/servers"
  chown "$u" "$dir" "$dir/servers" 2>/dev/null || true
  for f in "${TEMPLATES[@]}"; do
    if [[ ! -f "$dir/$f" ]]; then
      [[ -f "$REPO_DIR/examples/$f" ]] || die "Нет шаблона: $REPO_DIR/examples/$f"
      install -m 0644 "$REPO_DIR/examples/$f" "$dir/$f"
      chown "$u" "$dir/$f" 2>/dev/null || true
      log "Создан файл данных: $dir/$f (шаблон)"
    else
      log "Существующий файл не тронут: $dir/$f"
    fi
  done
}

# --- pf anchor ----------------------------------------------------------------
# Якорь должен быть объявлен в main ruleset, иначе правила грузятся, но не
# выполняются. Ставим placeholder-файл и строку anchor "com.sshtun" в pf.conf
# (idempotent: не дублируем, если уже есть).
setup_pf_anchor() {
  if [[ ! -f "$PF_ANCHOR_FILE" ]]; then
    cat > "$PF_ANCHOR_FILE" <<'EOF'
# sshtun managed anchor. Runtime-правила генерирует sshtun_macos.sh
# (/var/run/sshtun/pf/anchor.conf) и грузит через
#   pfctl -a com.sshtun -f /var/run/sshtun/pf/anchor.conf
# Этот файл — маркер + точка включения через anchor "com.sshtun" в /etc/pf.conf.
EOF
    log "pf-anchor файл: $PF_ANCHOR_FILE"
  fi
  if [[ -f "$PF_CONF" ]] && grep -q "anchor \"com.sshtun\"" "$PF_CONF" 2>/dev/null; then
    log "anchor \"com.sshtun\" уже есть в $PF_CONF"
  else
    printf '\n# vpn_over_ssh client anchor\nanchor "com.sshtun"\n' >> "$PF_CONF"
    log "Добавлен anchor \"com.sshtun\" в $PF_CONF (pf перечитает при следующем pfctl -f или старте туннеля)"
  fi
}

remove_pf_anchor() {
  rm -f "$PF_ANCHOR_FILE"
  if [[ -f "$PF_CONF" ]]; then
    local tmp=""
    tmp="$(mktemp)"
    grep -v 'anchor "com.sshtun"' "$PF_CONF" | grep -v '^# vpn_over_ssh client anchor$' > "$tmp" || true
    # убрать возможный осиротевший пустой хвост
    cat "$tmp" > "$PF_CONF"
    rm -f "$tmp"
    log "anchor убран из $PF_CONF"
  fi
}

# --- launchd ------------------------------------------------------------------
write_plist() {
  cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$SERVICE_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_DIR/$LINK_NAME</string>
    <string>up</string>
    <string>--foreground</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <!-- brew bash (>=4.3) раньше системного 3.2; Tailscale и пр. не ломаем -->
    <key>PATH</key>
    <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key>
  <false/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_FILE</string>
  <key>StandardErrorPath</key>
  <string>$LOG_FILE</string>
</dict>
</plist>
EOF
  chmod 0644 "$PLIST_PATH"
  log "LaunchDaemon plist: $PLIST_PATH (выключен: RunAtLoad=false; включение — в HOWTO-macos §5)"
}

service_enable() {
  launchctl bootstrap system "$PLIST_PATH" 2>/dev/null \
    || launchctl load -w "$PLIST_PATH" 2>/dev/null \
    || die "launchctl bootstrap не удался"
  log "Служба запущена: launchctl print system/$SERVICE_LABEL"
}
service_disable() {
  launchctl bootout "system/$SERVICE_LABEL" 2>/dev/null \
    || launchctl unload "$PLIST_PATH" 2>/dev/null || true
}

# --- команды ------------------------------------------------------------------
do_install() {
  check_deps
  install_files
  seed_data
  setup_pf_anchor
  write_plist
  cat <<EOF

[OK] vpn_over_ssh macOS client installed

Команды:
  $LINK_NAME up / down / restart / status / list
  $LINK_NAME server list / add / use   (профили серверов, как на Linux)
  $LINK_NAME --help

До первого подключения:
  1) ключ: ssh-keygen -t ed25519 -f ~/.ssh/sshtun_ed25519 -N "" -C "\$(whoami)-\$(hostname)"
  2) публичный ключ добавить на сервер в /opt/sshtun_pool/authorized_keys
  3) адрес сервера: $LINK_NAME server add fin <host> -- "мой сервер" && $LINK_NAME server use fin
     (или вручную ~/sshtun/server.conf: SERVER_HOST=<host>)

Служба (досмотр launchd, аналог systemd):
  включить:  sudo launchctl bootstrap system $PLIST_PATH
  выключить: sudo launchctl bootout system/$SERVICE_LABEL
  лог:       tail -f $LOG_FILE
EOF
}

do_uninstall() {
  service_disable
  rm -f "$PLIST_PATH" "$BIN_DIR/$LINK_NAME"
  remove_pf_anchor
  rm -rf "$INSTALL_DIR"
  log "Скрипты, plist, anchor удалены. Данные (~/sshtun) и лог ($LOG_FILE) оставлены."
}

cmd="${1:-install}"
case "$cmd" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  reinstall) do_uninstall; do_install ;;
  *) die "Неизвестная команда: $cmd (нужно install|uninstall|reinstall)" ;;
esac
