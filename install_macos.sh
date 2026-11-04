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
INSTALL_USER="${SUDO_USER:-$USER}"
INSTALL_USER_HOME="$(eval echo "~$INSTALL_USER" 2>/dev/null || echo "$HOME")"
# bash >= 4.3 ищем: явный выбор, brew (Intel/ARM), локальная сборка
# ~/sshtun-tools (ставится скриптом prepare_macos.sh, если нет brew).
# Массив, а не строка: в скрипте IFS без пробела, word-splitting не сработал бы.
BASH_BIN_CANDIDATES=()
[[ -n "${BASH_BIN:-}" ]] && BASH_BIN_CANDIDATES+=("$BASH_BIN")
BASH_BIN_CANDIDATES+=(/usr/local/bin/bash /opt/homebrew/bin/bash "$INSTALL_USER_HOME/sshtun-tools/bin/bash")

log(){ echo "[install] $*"; }
die(){ echo "[install][ERROR] $*" >&2; exit 1; }

# --- зависимости ------------------------------------------------------------
bash_version_ok() { # path -> 0 если >= 4.3
  [[ -x "$1" ]] || return 1
  local v=""
  v="$("$1" -c 'printf "%s" "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"' 2>/dev/null || true)"
  [[ -n "$v" ]] || return 1
  "$1" -c 'exit $(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) ? 0 : 1 ))'
}

detect_bash() {
  local c="" found=""
  for c in "${BASH_BIN_CANDIDATES[@]}"; do
    if bash_version_ok "$c"; then found="$c"; break; fi
  done
  if [[ -z "$found" ]]; then
    die "Нужен bash >= 4.3. Варианты: brew install bash | либо
  bash prepare_macos.sh   # соберёт bash в ~/sshtun-tools из исходников (CLT)"
  fi
  BASH_BIN="$found"
  log "bash: $BASH_BIN ($("$BASH_BIN" -c 'printf "%s" "$BASH_VERSION"'))"
}

check_deps() {
  detect_bash
  # ssh с поддержкой -w/utun: Apple ssh НЕ подходит. Ищем собранный
  # (prepare_macos.sh -> ~/sshtun-tools) или brew openssh.
  SSH_USABLE=""
  local c=""
  for c in "$INSTALL_USER_HOME/sshtun-tools/bin/ssh" /usr/local/bin/ssh /opt/homebrew/bin/ssh; do
    if [[ -x "$c" && "$c" != /usr/bin/ssh && "$c" != /bin/ssh ]]; then SSH_USABLE="$c"; break; fi
  done
  [[ -n "$SSH_USABLE" ]] || die "ssh без поддержки -w (Apple ssh). Выполните:
  bash prepare_macos.sh   # соберёт LibreSSL + OpenSSH в ~/sshtun-tools"
  log "ssh (с -w): $SSH_USABLE ($("$SSH_USABLE" -V 2>&1 | head -n1))"
  for c in ssh python3 ifconfig networksetup pfctl route dig; do
    command -v "$c" >/dev/null 2>&1 || die "Нет утилиты: $c (python3/dig — Xcode CLT: xcode-select --install)"
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
  # Root-хелпер — ЕДИНСТВЕННая команда в NOPASSWD-sudoers (см. setup_sudoers).
  [[ -f "$REPO_DIR/sshtun_root.sh" ]] || die "Нет файла в репозитории: $REPO_DIR/sshtun_root.sh"
  install -m 0755 -o root -g wheel "$REPO_DIR/sshtun_root.sh" "$INSTALL_DIR/sshtun-root"
  log "Root-хелпер: $INSTALL_DIR/sshtun-root (root:wheel 0755)"
  # Go data-plane (tun@openssh.com в userspace — замена «ssh -w» на macOS).
  # В репо обе архитектуры (кросс-сборка): installer выбирает под uname -m.
  # Пересборка: cd sshtun_macos_client && GOOS=darwin GOARCH=amd64|arm64 go build
  local _dp_bin=""
  case "$(uname -m 2>/dev/null || echo x86_64)" in
    arm64|aarch64) _dp_bin="sshtun-macos-tun.arm64" ;;
    *) _dp_bin="sshtun-macos-tun.amd64" ;;
  esac
  if [[ -f "$REPO_DIR/sshtun_macos_client/$_dp_bin" ]]; then
    install -m 0755 -o root -g wheel "$REPO_DIR/sshtun_macos_client/$_dp_bin" "$INSTALL_DIR/sshtun-macos-tun"
    log "Data-plane: $INSTALL_DIR/sshtun-macos-tun ($_dp_bin)"
  elif [[ -f "$REPO_DIR/sshtun_macos_client/sshtun-macos-tun" ]]; then
    # legacy: единичная сборка без архитектурного суффикса
    install -m 0755 -o root -g wheel "$REPO_DIR/sshtun_macos_client/sshtun-macos-tun" "$INSTALL_DIR/sshtun-macos-tun"
    log "Data-plane: $INSTALL_DIR/sshtun-macos-tun (legacy, без суффикса архитектуры)"
  else
    log "Data-plane: бинарь sshtun_macos_client/$_dp_bin не найден — соберите (go build), без него up не заработает"
  fi
  # env.conf: путь к ssh с -w (Apple ssh не умеет utun) и к bash >= 4.3
  # (иначе sudo/helper может запустить системный 3.2, который падает на
  # "${arr[@]}" под set -u). Source'ится обёрткой, бэкендом и хелпером,
  # в т.ч. под root, где $HOME указывает в /var/root.
  {
    printf '# generated by install_macos.sh — не править\n'
    printf 'SSH_BIN=%q\n' "$SSH_USABLE"
    printf 'BASH_BIN=%q\n' "$BASH_BIN"
    printf 'SSHTUN_BACKEND=%q\n' "$REPO_DIR/sshtun_macos.sh"
  } > "$INSTALL_DIR/env.conf"
  chmod 0644 "$INSTALL_DIR/env.conf"
  log "env.conf: SSH_BIN=$SSH_USABLE BASH_BIN=$BASH_BIN SSHTUN_BACKEND=$REPO_DIR/sshtun_macos.sh"
  # Шим вместо symlink на скрипт: гарантированно запускает НУЖНЫЙ bash
  # (системный 3.2 не подходит) и ЖИВУЮ обёртку из репозитория — дальше
  # правки обёртки/бэкенда подхватываются git pull без root и без переустановки.
  cat > "$BIN_DIR/$LINK_NAME" <<EOF
#!/bin/sh
# generated by install_macos.sh — не править
exec "$BASH_BIN" "$REPO_DIR/sshtun_full.sh" "\$@"
EOF
  chmod 0755 "$BIN_DIR/$LINK_NAME"
  log "Шим: $BIN_DIR/$LINK_NAME (bash: $BASH_BIN, wrapper: $REPO_DIR/sshtun_full.sh)"
}

seed_data() {
  local home="$INSTALL_USER_HOME"
  [[ -d "$home" ]] || { log "Домашний каталог $INSTALL_USER не найден — seed пропущен"; return 0; }
  local dir="$home/sshtun" f=""
  mkdir -p "$dir/servers"
  chown "$INSTALL_USER" "$dir" "$dir/servers" 2>/dev/null || true
  for f in "${TEMPLATES[@]}"; do
    if [[ ! -f "$dir/$f" ]]; then
      [[ -f "$REPO_DIR/examples/$f" ]] || die "Нет шаблона: $REPO_DIR/examples/$f"
      install -m 0644 "$REPO_DIR/examples/$f" "$dir/$f"
      chown "$INSTALL_USER" "$dir/$f" 2>/dev/null || true
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

# --- sudoers ------------------------------------------------------------------
# NOPASSWD ровно для одной команды — root-хелпера. env_keep пропускает
# TUN_NET_* через sudo в бэкенд. Валидация через visudo обязательна:
# битый sudoers = потерянный sudo.
SUDOERS_FILE="/etc/sudoers.d/sshtun"
setup_sudoers() {
  local tmp=""
  tmp="$(mktemp)"
  cat > "$tmp" <<EOF
# vpn_over_ssh client: passwordless sudo только для root-хелпера.
# Обновляется install_macos.sh; удаляется uninstall'ом.
Defaults env_keep += "TUN_NET_A TUN_NET_B"
$INSTALL_USER ALL=(ALL) NOPASSWD: $INSTALL_DIR/sshtun-root
EOF
  chmod 0440 "$tmp"
  visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "visudo отклонил $SUDOERS_FILE"; }
  install -m 0440 -o root -g wheel "$tmp" "$SUDOERS_FILE"
  rm -f "$tmp"
  log "sudoers: $SUDOERS_FILE (NOPASSWD: sshtun-root только)"
}

remove_sudoers() { rm -f "$SUDOERS_FILE"; log "sudoers убран: $SUDOERS_FILE"; }

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
    <!-- Служба идёт ОТ ROOT: HOME не задан (set -u падает) и указывал бы
    в /var/root. Пути к данным/ключу пользователя задаём явно (паритет с
    Environment= в systemd-юните Linux-клиента). -->
    <key>EXCLUDES_DIR</key>
    <string>$INSTALL_USER_HOME/sshtun</string>
    <key>KEY_FILE</key>
    <string>$INSTALL_USER_HOME/.ssh/sshtun_ed25519</string>
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
  log "LaunchDaemon plist: $PLIST_PATH (выключен: RunAtLoad=false; включение: sudo $INSTALL_DIR/sshtun-root service-start)"
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
  setup_sudoers
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
  включить:  sudo $INSTALL_DIR/sshtun-root service-start   # bootout+bootstrap, дальше KeepAlive
  выключить: sudo $INSTALL_DIR/sshtun-root service-stop    # или: launchctl bootout system/$SERVICE_LABEL
  лог:       tail -f $LOG_FILE
EOF
}

do_uninstall() {
  service_disable
  rm -f "$PLIST_PATH" "$BIN_DIR/$LINK_NAME"
  remove_pf_anchor
  remove_sudoers
  rm -rf "$INSTALL_DIR"
  log "Скрипты, plist, anchor, sudoers удалены. Данные (~/sshtun) и лог ($LOG_FILE) оставлены."
}

cmd="${1:-install}"
case "$cmd" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  reinstall) do_uninstall; do_install ;;
  *) die "Неизвестная команда: $cmd (нужно install|uninstall|reinstall)" ;;
esac
