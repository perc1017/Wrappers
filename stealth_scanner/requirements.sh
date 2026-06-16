#!/bin/bash


set -e

echo "========================================================="
echo "   Глобальная установка зависимостей (APT + PEP 668 Fix)"
echo "========================================================="

echo "[*] Обновление списков пакетов (apt update)..."
sudo apt update -y

echo "[*] Установка системного Nmap и утилит Python..."
sudo apt install nmap python3-pip python3-full -y
echo "[*] Очистка старых конфликтующих пакетов..."
sudo pip3 uninstall -y nmap python-nmap aiohttp --break-system-packages || true

echo "[*] Установка python-nmap и aiohttp в глобальное окружение..."
sudo pip3 install python-nmap aiohttp --break-system-packages

echo "========================================================="
echo "[+] Установка завершена! "
echo "[*] Теперь вы можете спокойно запускать свой сканер:"
echo "    sudo python3 stealth_scanner_apt.py <target>"
echo "========================================================="