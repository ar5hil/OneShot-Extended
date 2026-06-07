#!/data/data/com.termux/files/usr/bin/bash

set -e

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

echo "[*] Updating Termux packages..."
pkg update -y && pkg upgrade -y

echo "[*] Installing root repo..."
pkg install -y root-repo

echo "[*] Installing dependencies..."
pkg install -y git tsu python wpa-supplicant pixiewps iw openssl iproute2

echo "[*] Installing Python packages..."
pip install rich

echo "[*] Cloning OneShot-Extended..."
cd "$HOME"
if [ -d "ose" ]; then
    echo "[*] Directory 'ose' exists, updating..."
    cd ose && git pull
else
    git clone https://github.com/ar5hil/OneShot-Extended ose
    cd ose
fi

echo "[*] Creating symlink: ose -> $PREFIX/bin/ose"
ln -sf "$(pwd)/ose.py" "$PREFIX/bin/ose"
chmod +x ose.py

echo ""
echo "[+] OneShot-Extended installed successfully!"
echo "[+] Run with: tsu -- ose -i wlan0 -P"
echo "[+] Auto-pixie mode: tsu -- ose -i wlan0 -A"
