import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

WEB_PORTS        = {80, 443, 8080, 8443, 8000, 8888}
DEFAULT_WORDLIST = Path(__file__).parent / "medium.txt"
DEFAULT_RATE     = 2000          
TOOL_TIMEOUT     = 300           
SCAN_TIMEOUT     = 600           

BANNER = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Multi-stage automated reconnaissance pipeline.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target", required=False,
        help="Target domain or IP address (e.g. example.com or 10.0.0.1)",
    )
    parser.add_argument(
        "-w", "--wordlist", default=str(DEFAULT_WORDLIST),
        help=f"Path to wordlist for fuzzing (default: {DEFAULT_WORDLIST})",
    )
    parser.add_argument(
        "-o", "--output-dir", default=".",
        help="Directory to write reports into (default: current dir)",
    )
    parser.add_argument(
        "--rate", type=int, default=DEFAULT_RATE,
        help=f"Masscan packets/sec (default: {DEFAULT_RATE}; needs root)",
    )
    parser.add_argument(
        "--skip-masscan", action="store_true",
        help="Skip masscan (useful when not running as root)",
    )
    parser.add_argument(
        "--skip-vuln", action="store_true",
        help="Skip vulnerability scanning phase (Nuclei/Nikto/SQLMap/Amass)",
    )
    parser.add_argument(
        "--skip-fuzz", action="store_true",
        help="Skip web fuzzing phase",
    )
    parser.add_argument(
        "--ports", default=None,
        help="Comma-separated ports to scan directly (skips port discovery)",
    )
    return parser.parse_args()

VALID_TARGET_RE = re.compile(
    r'^(?:[a-zA-Z0-9]'           
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  
    r'|\[?[0-9a-fA-F:]+\]?)$'               
)

def validate_target(target: str) -> str:
    """Validate and sanitize target to prevent shell injection."""
    target = target.strip()
    if not target:
        sys.exit("[-] Error: Target must not be empty.")

    for family in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        try:
            family(target)
            return target
        except ValueError:
            pass

    if VALID_TARGET_RE.match(target):
        return target

    sys.exit(f"[-] Error: Invalid target '{target}'. Use a valid domain or IP.")


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def check_tool(name: str) -> bool:
    return shutil.which(name) is not None

def check_tools(required: list[str], optional: list[str]) -> None:
    missing_req = [t for t in required if not check_tool(t)]
    missing_opt = [t for t in optional if not check_tool(t)]

    if missing_req:
        sys.exit(f"[-] Missing required tools: {', '.join(missing_req)}\n"
                 "    Install them before running this script.")
    if missing_opt:
        print(f"[!] Optional tools not found (phases may be skipped): "
              f"{', '.join(missing_opt)}")

class Logger:
    def __init__(self, raw_log_path: Path):
        self.path = raw_log_path
        self.path.write_text("", encoding="utf-8")  

    def write(self, text: str):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text + "\n" + "─" * 60 + "\n")


def run_command(
    cmd: str,
    logger: Logger,
    timeout: int = TOOL_TIMEOUT,
    env: dict | None = None,
) -> tuple[str, str]:
    """
    Run a shell command safely.
    Returns (stdout, stderr). Never raises on non-zero exit.
    """
    print(f"    → {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ.copy(),
        )
        logger.write(
            f"CMD: {cmd}\n"
            f"EXIT: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        if result.returncode != 0 and result.stderr.strip():
            print(f"    [!] Tool warning (exit {result.returncode}): "
                  f"{result.stderr.strip()[:200]}")
        return result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        msg = f"[!] Command timed out after {timeout}s: {cmd}"
        print(msg)
        logger.write(f"CMD: {cmd}\nTIMEOUT after {timeout}s")
        return "", "TIMEOUT"

    except Exception as exc:
        msg = f"[!] Unexpected error running '{cmd}': {exc}"
        print(msg)
        logger.write(f"CMD: {cmd}\nERROR: {exc}")
        return "", str(exc)

def parse_masscan_output(path: Path) -> set[int]:
    ports: set[int] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.search(r"open\s+tcp\s+(\d+)", line)
            if m:
                ports.add(int(m.group(1)))
    except Exception as exc:
        print(f"    [!] Could not parse masscan output: {exc}")
    return ports


def parse_nmap_greppable(path: Path) -> set[int]:
    ports: set[int] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "Ports:" not in line:
                continue
            ports_section = line.split("Ports:")[1].strip()
            for item in ports_section.split(","):
                item = item.strip()
                # format: port/state/proto/...
                parts = item.split("/")
                if len(parts) >= 2 and parts[1] == "open":
                    try:
                        ports.add(int(parts[0]))
                    except ValueError:
                        pass
    except Exception as exc:
        print(f"    [!] Could not parse nmap greppable output: {exc}")
    return ports


def scan_ports_phase_1(
    target: str,
    logger: Logger,
    rate: int,
    skip_masscan: bool,
) -> list[int]:
    print("\n[*] ══ PHASE 1: Port Discovery (Masscan + Nmap) ══")
    found_ports: set[int] = set()
    tmp_masscan = Path("masscan.tmp")
    tmp_nmap    = Path("nmap_fast.tmp")

    if skip_masscan:
        print("    [~] Masscan skipped (--skip-masscan).")
    elif not check_tool("masscan"):
        print("    [!] masscan not found — skipping.")
    elif os.geteuid() != 0:
        print("    [!] masscan requires root privileges — skipping. "
              "Re-run as root or use --skip-masscan.")
    else:
        run_command(
            f"masscan {target} -p1-65535 --rate {rate} --wait 5 -oL {tmp_masscan}",
            logger,
            timeout=SCAN_TIMEOUT,
        )
        if tmp_masscan.exists():
            found_ports |= parse_masscan_output(tmp_masscan)
            tmp_masscan.unlink(missing_ok=True)

    run_command(
        f"nmap -F -Pn --open {target} -oG {tmp_nmap}",
        logger,
        timeout=TOOL_TIMEOUT,
    )
    if tmp_nmap.exists():
        found_ports |= parse_nmap_greppable(tmp_nmap)
        tmp_nmap.unlink(missing_ok=True)

    sorted_ports = sorted(found_ports)
    print(f"[+] Unique open ports found: {sorted_ports if sorted_ports else 'none'}")
    return sorted_ports

def deep_nmap_scan(target: str, ports: list[int], logger: Logger) -> str:
    print("\n[*] ══ PHASE 2: Deep Nmap Service/Script Scan ══")
    if not ports:
        print("    [-] No ports to scan. Skipping.")
        return "No open ports discovered."

    ports_str = ",".join(map(str, ports))
    vulners_flag = "--script=vulners" if check_tool("nmap") else ""
    cmd = (
        f"nmap -sV -sC {vulners_flag} -Pn --open "
        f"-p{ports_str} {target}"
    )
    stdout, _ = run_command(cmd, logger, timeout=SCAN_TIMEOUT)
    return stdout or "Nmap returned no output."

def web_fuzzing_phase(
    target: str,
    ports: list[int],
    wordlist: Path,
    logger: Logger,
) -> str:
    print("\n[*] ══ PHASE 3: Web Directory Fuzzing ══")

    if not wordlist.exists():
        msg = (f"[-] Wordlist not found: {wordlist}\n"
               "    Place medium.txt in the script directory or use -w.")
        print(msg)
        return msg

    web_ports = [p for p in ports if p in WEB_PORTS]
    if not web_ports:
        print("    [-] No web ports detected. Skipping fuzzing.")
        return "No web ports detected."

    results: list[str] = []
    seen_paths: set[str] = set()  

    for port in web_ports:
        proto = "https" if port == 443 else "http"
        url   = f"{proto}://{target}:{port}/"
        print(f"\n    [+] Target: {url}")
        port_results: list[str] = []

        if check_tool("ffuf"):
            out, _ = run_command(
                f"ffuf -u {url}FUZZ -w {wordlist} -mc 200,301,302,403 -s",
                logger,
            )
            deduped = _dedup_lines(out, seen_paths)
            port_results.append(f"─── ffuf → {url} ───\n{deduped}")
        else:
            port_results.append("ffuf: not installed")

        if check_tool("gobuster"):
            out, _ = run_command(
                f"gobuster dir -u {url} -w {wordlist} -q --no-progress "
                f"-k --timeout 10s",
                logger,
            )
            deduped = _dedup_lines(out, seen_paths)
            port_results.append(f"─── gobuster → {url} ───\n{deduped}")
        else:
            port_results.append("gobuster: not installed")

        if check_tool("feroxbuster"):
            out, _ = run_command(
                f"feroxbuster -u {url} -w {wordlist} --silent -n -k",
                logger,
            )
            deduped = _dedup_lines(out, seen_paths)
            port_results.append(f"─── feroxbuster → {url} ───\n{deduped}")
        else:
            port_results.append("feroxbuster: not installed")

        results.append("\n".join(port_results))

    return "\n\n".join(results)


def _dedup_lines(text: str, seen: set[str]) -> str:
    """Remove duplicate result lines across tool calls."""
    unique: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            unique.append(line)
        elif not stripped:
            unique.append(line)
    return "\n".join(unique)

def vulnerability_scanning(target: str, logger: Logger) -> str:
    print("\n[*] ══ PHASE 4: Vulnerability & Intelligence Gathering ══")
    results: list[str] = []

    if is_ip(target):
        results.append("=== AMASS: Skipped (target is an IP address) ===")
    elif not check_tool("amass"):
        results.append("=== AMASS: Not installed ===")
    else:
        print("    [+] Running Amass passive subdomain enumeration...")
        out, _ = run_command(
            f"amass enum -passive -d {target}",
            logger,
            timeout=SCAN_TIMEOUT,
        )
        results.append(f"=== SUBDOMAINS (Amass) ===\n{out or 'No results.'}")

    if not check_tool("nikto"):
        results.append("=== NIKTO: Not installed ===")
    else:
        print("    [+] Running Nikto web scan...")
        out, _ = run_command(
            f"nikto -h {target} -Tuning 1,2,3,4,8,9",
            logger,
            timeout=SCAN_TIMEOUT,
        )
        results.append(f"=== WEB VULNERABILITIES (Nikto) ===\n{out or 'No results.'}")

    if not check_tool("nuclei"):
        results.append("=== NUCLEI: Not installed ===")
    else:
        print("    [+] Running Nuclei template scan...")
        out, _ = run_command(
            f"nuclei -u http://{target} -silent -severity low,medium,high,critical",
            logger,
            timeout=SCAN_TIMEOUT,
        )
        results.append(f"=== CVE / TEMPLATE MATCHES (Nuclei) ===\n{out or 'No results.'}")

    if not check_tool("sqlmap"):
        results.append("=== SQLMAP: Not installed ===")
    else:
        print("    [+] Running SQLMap injection scan...")
        out, _ = run_command(
            f"sqlmap -u 'http://{target}/' --crawl=2 --batch --forms "
            f"--level=1 --risk=1 --output-dir=sqlmap_output",
            logger,
            timeout=SCAN_TIMEOUT,
        )
        results.append(f"=== SQL INJECTION ANALYSIS (SQLMap) ===\n{out or 'No results.'}")

    return "\n\n".join(results)


def write_final_report(
    output_dir: Path,
    target: str,
    ports: list[int],
    nmap_report: str,
    fuzz_report: str,
    vuln_report: str,
    elapsed: float,
) -> Path:
    report_path = output_dir / "final_recon_report.txt"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    web_ports_found = [p for p in ports if p in WEB_PORTS]

    lines = [
        "╔══════════════════════════════════════════════════════════╗",
        f"║  RECON REPORT  ·  TARGET: {target:<32}║",
        f"║  Generated: {ts}                          ║",
        "╚══════════════════════════════════════════════════════════╝",
        "",
        "┌─ EXECUTIVE SUMMARY ────────────────────────────────────────",
        f"│  Open ports    : {', '.join(map(str, ports)) or 'None found'}",
        f"│  Web ports     : {', '.join(map(str, web_ports_found)) or 'None'}",
        f"│  Scan duration : {elapsed/60:.2f} minutes",
        "└────────────────────────────────────────────────────────────",
        "",
        "═" * 62,
        "1. OPEN PORTS",
        "═" * 62,
        ", ".join(map(str, ports)) if ports else "None discovered.",
        "",
        "═" * 62,
        "2. SERVICE & VULNERABILITY DETAILS (Nmap)",
        "═" * 62,
        nmap_report,
        "",
        "═" * 62,
        "3. WEB DIRECTORY FUZZING (ffuf / gobuster / feroxbuster)",
        "═" * 62,
        fuzz_report,
        "",
        "═" * 62,
        "4. VULNERABILITY & INTELLIGENCE GATHERING",
        "   (Nuclei / Nikto / SQLMap / Amass)",
        "═" * 62,
        vuln_report,
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def main() -> None:
    print(BANNER)
    args = parse_args()

    if not args.target:
        args.target = input("Enter target domain or IP: ").strip()

    target     = validate_target(args.target)
    wordlist   = Path(args.wordlist)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_log = output_dir / "raw_recon.log"
    logger  = Logger(raw_log)

    print(f"[*] Target     : {target}")
    print(f"[*] Wordlist   : {wordlist}")
    print(f"[*] Output dir : {output_dir}")

    check_tools(
        required=["nmap"],
        optional=["masscan", "ffuf", "gobuster", "feroxbuster",
                  "nuclei", "nikto", "sqlmap", "amass"],
    )

    start_time = time.time()

    if args.ports:
        try:
            ports = sorted({int(p.strip()) for p in args.ports.split(",")})
            print(f"\n[*] Using user-supplied ports: {ports}")
        except ValueError:
            sys.exit("[-] --ports must be a comma-separated list of integers.")
    else:
        ports = scan_ports_phase_1(target, logger, args.rate, args.skip_masscan)

    nmap_report = deep_nmap_scan(target, ports, logger)

    fuzz_report = (
        web_fuzzing_phase(target, ports, wordlist, logger)
        if not args.skip_fuzz
        else "Fuzzing skipped via --skip-fuzz."
    )

    vuln_report = (
        vulnerability_scanning(target, logger)
        if not args.skip_vuln
        else "Vulnerability scanning skipped via --skip-vuln."
    )

    elapsed     = time.time() - start_time
    report_path = write_final_report(
        output_dir, target, ports,
        nmap_report, fuzz_report, vuln_report,
        elapsed,
    )

    print("\n" + "═" * 62)
    print(f"[+] Scan completed in {elapsed/60:.2f} minutes.")
    print(f"[+] Raw tool log : {raw_log}")
    print(f"[+] Final report : {report_path}")
    print("═" * 62)


if __name__ == "__main__":
    main()