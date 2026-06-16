import os
import sys
import time
import random
import asyncio
import logging
import ipaddress
import nmap
import aiohttp

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("stealth_scan.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
]

DEFAULT_WORDLIST = ["robots.txt", ".env", "admin", "login", "api"]

def scan_ports(target):
    logging.info(f"Начало Nmap сканирования для: {target}")
    nm = nmap.PortScanner()
    arguments = "-sS -sV -T2 --top-ports 50 --randomize-hosts"
    
    scan_results = {}
    try:
        nm.scan(hosts=target, arguments=arguments)
    except Exception as e:
        logging.error(f"Критическая ошибка Nmap при сканировании цели {target}: {e}")
        return scan_results

    for host in nm.all_hosts():
        try:
            scan_results[host] = []
            for proto in nm[host].all_protocols():
                sorted_ports = sorted(nm[host][proto].keys())
                for port in sorted_ports:
                    port_data = nm[host][proto][port]
                    if port_data['state'] == 'open':
                        service_name = port_data.get('name', '').lower()
                        
                        scan_results[host].append({
                            "port": port, 
                            "proto": proto,
                            "service": service_name
                        })
        except Exception as host_error:
            logging.error(f"Ошибка при обработке данных хоста {host}: {host_error}")
            
    return scan_results

async def check_url(session, base_url, path):
    await asyncio.sleep(random.uniform(1.0, 3.0))
    url = f"{base_url}/{path}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    
    try:
        async with session.get(url, headers=headers, allow_redirects=False) as response:
            if response.status in [200, 301, 302, 403]:
                return {"path": f"/{path}", "status": response.status}
    except Exception:
        pass
    return None

async def scan_web_port(target, port, use_ssl=False, wordlist=DEFAULT_WORDLIST):
    protocol = "https" if use_ssl else "http"
    base_url = f"{protocol}://{target}:{port}"
    
    logging.info(f"Начало веб-сканирования на порту {port} ({protocol.upper()}): {base_url}")
    
    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(limit=2, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_url(session, base_url, path.strip()) for path in wordlist]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
    
def print_port_results(scan_data):
    if not scan_data:
        print("\n[-] Открытых портов не обнаружено.")
        return

    print("\n=== РЕЗУЛЬТАТЫ СКАНЕРА ПОРТОВ ===")
    for host, ports in scan_data.items():
        print(f"\n[+] Хост: {host}")
        for p_info in ports:
            service_str = f" (Служба: {p_info['service']})" if p_info['service'] else ""
            print(f"    └─ [ОТКРЫТ] Порт: {p_info['port']} | Протокол: {p_info['proto'].upper()}{service_str}")

def print_web_results(web_data, port, protocol_name):
    if not web_data:
        print(f"\n[*] На порту {port} ({protocol_name}) ничего интересного не найдено.")
        return
    print(f"\n=== НАЙДЕННЫЕ ВЕБ-ДИРЕКТОРИИ (Порт: {port} | {protocol_name}) ===")
    for item in web_data:
        print(f"    └─ Найдено: {item['path']} (Статус: {item['status']})")

def main():
    if len(sys.argv) < 2:
        print(f"Использование: python {sys.argv[0]} <target>")
        sys.exit(1)
        
    target = sys.argv[1]
    
    is_ip = True
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False 
    
    logging.info(f"Сканирование запущено. Цель: {target} (Тип: {'IP' if is_ip else 'Домен'})")
    
    scan_data = scan_ports(target)
    print_port_results(scan_data)
    
    fallback_http_ports = [80, 8080]
    fallback_https_ports = [443, 8443]
    
    web_scanned = False

    for host, ports in scan_data.items():
        for p_info in ports:
            port = p_info['port']
            service = p_info['service']
            
            is_https_service = "https" in service or "ssl" in service or port in fallback_https_ports
            
            is_web_service = "http" in service or "www" in service or is_https_service or port in fallback_http_ports

            if is_web_service:
                web_scanned = True
                
                use_ssl = True if is_https_service else False
                proto_name = "HTTPS" if use_ssl else "HTTP"
                
                if port not in [80, 443, 8080, 8443]:
                    logging.info(f"[!] Обнаружен нестандартный веб-порт {port} через сигнатуру службы '{service}'")
                
                results = asyncio.run(scan_web_port(target, port, use_ssl=use_ssl))
                print_web_results(results, port, proto_name)

    if not is_ip and not web_scanned:
        logging.info("[*] Открытых веб-портов не найдено, но цель — домен. Проверяем стандартные 80 и 443.")
        
        http_results = asyncio.run(scan_web_port(target, 80, use_ssl=False))
        print_web_results(http_results, 80, "HTTP")
        
        https_results = asyncio.run(scan_web_port(target, 443, use_ssl=True))
        print_web_results(https_results, 443, "HTTPS")

    logging.info("Сканирование успешно завершено.")

if __name__ == "__main__":
    if os.name != 'nt' and os.geteuid() != 0:
        logging.error("Для работы SYN-сканирования (Nmap -sS) требуются права root (sudo).")
        sys.exit(1)
    main()