#!/usr/bin/env bash
# Собрать зависимости macOS-клиента, которых нет в системе (без brew/root,
# нужен Xcode CLT), в ~/sshtun-tools:
#   - bash >= 4.3 (системный 3.2 не умеет nameref/ассоциативные массивы)
#   - LibreSSL + OpenSSH-клиент (Apple ssh НЕ умеет -w/utun:
#     «Tunnel device open failed» — туннель на macOS без него не работает)
set -euo pipefail

BASH_VER="${BASH_VER:-5.2}"
LIBRESSL_VER="${LIBRESSL_VER:-3.9.2}"
OPENSSH_VER="${OPENSSH_VER:-9.9p2}"
PREFIX="${PREFIX:-$HOME/sshtun-tools}"
JOBS="${JOBS:-4}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() { # url dest
  echo "[prepare] curl $1"
  curl -fsSL "$1" -o "$2"
}

echo "[prepare] prefix: $PREFIX"

if [[ ! -x "$PREFIX/bin/bash" ]] || ! "$PREFIX/bin/bash" -c '(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) ))'; then
  fetch "https://ftp.gnu.org/gnu/bash/bash-${BASH_VER}.tar.gz" "$WORK/bash.tar.gz"
  tar xzf "$WORK/bash.tar.gz" -C "$WORK"
  ( cd "$WORK/bash-${BASH_VER}" \
    && ./configure --prefix="$PREFIX" --without-bash-malloc >"$WORK/bash-conf.log" 2>&1 \
    && make -j"$JOBS" >"$WORK/bash-make.log" 2>&1 \
    && make install >"$WORK/bash-inst.log" 2>&1 )
  echo "[prepare] bash OK: $("$PREFIX/bin/bash" --version | head -n1)"
else
  echo "[prepare] bash уже есть: $("$PREFIX/bin/bash" --version | head -n1)"
fi

if [[ ! -x "$PREFIX/bin/ssh" ]]; then
  fetch "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER}.tar.gz" "$WORK/libressl.tar.gz"
  tar xzf "$WORK/libressl.tar.gz" -C "$WORK"
  ( cd "$WORK/libressl-${LIBRESSL_VER}" \
    && ./configure --prefix="$PREFIX" >"$WORK/libressl-conf.log" 2>&1 \
    && make -j"$JOBS" >"$WORK/libressl-make.log" 2>&1 \
    && make install >"$WORK/libressl-inst.log" 2>&1 )
  echo "[prepare] LibreSSL OK"

  fetch "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VER}.tar.gz" "$WORK/openssh.tar.gz"
  tar xzf "$WORK/openssh.tar.gz" -C "$WORK"
  ( cd "$WORK/openssh-${OPENSSH_VER}" \
    && ./configure --prefix="$PREFIX" --with-ssl-dir="$PREFIX" --without-pam >"$WORK/openssh-conf.log" 2>&1 \
    && make -j"$JOBS" ssh >"$WORK/openssh-make.log" 2>&1 )
  cp "$WORK/openssh-${OPENSSH_VER}/ssh" "$PREFIX/bin/ssh"
  echo "[prepare] OpenSSH OK: $("$PREFIX/bin/ssh" -V 2>&1)"
else
  echo "[prepare] ssh уже есть: $("$PREFIX/bin/ssh" -V 2>&1)"
fi

echo "[prepare] OK. Теперь: sudo bash install_macos.sh install"
