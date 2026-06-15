#!/usr/bin/env bash

set -euo pipefail

sudo apt update
sudo apt install -y nmap masscan ffuf gobuster nikto sqlmap curl git snapd

sudo snap install amass || true
sudo snap install nuclei || true

for tool in amass nuclei; do
    if [ -f "/snap/bin/$tool" ] && [ ! -f "/usr/local/bin/$tool" ]; then
        sudo ln -s "/snap/bin/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
    fi
done

if ! command -v feroxbuster &> /dev/null; then
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
    sudo mv feroxbuster /usr/local/bin/
fi

if [ ! -f "medium.txt" ]; then
    curl -s -f -o medium.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
fi

TOOLS=("nmap" "masscan" "ffuf" "gobuster" "feroxbuster" "nuclei" "nikto" "sqlmap" "amass")
for tool in "${TOOLS[@]}"; do
    command -v "$tool" &> /dev/null
done