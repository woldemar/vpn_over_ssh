#!/usr/bin/env bash
# Собрать bash >= 4.3 из исходников в ~/sshtun-tools (без brew, без root).
# Нужен Xcode CLT (cc). Используется install_macos.sh как fallback, когда
# ни brew, ни готового bash 4.3+ в системе нет.
set -euo pipefail

BASH_VER="${BASH_VER:-5.2}"
PREFIX="${PREFIX:-$HOME/sshtun-tools}"
JOBS="${JOBS:-4}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[prepare] bash-$BASH_VER -> $PREFIX"
curl -fsSL "https://ftp.gnu.org/gnu/bash/bash-${BASH_VER}.tar.gz" -o "$WORK/bash.tar.gz"
tar xzf "$WORK/bash.tar.gz" -C "$WORK"
cd "$WORK/bash-${BASH_VER}"
./configure --prefix="$PREFIX" --without-bash-malloc >"$WORK/configure.log" 2>&1
make -j"$JOBS" >"$WORK/make.log" 2>&1
make install >"$WORK/install.log" 2>&1

"$PREFIX/bin/bash" --version | head -1
echo "[prepare] OK. Теперь: sudo bash install_macos.sh install"
