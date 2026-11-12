#!/usr/bin/env python3
import argparse
import sys
import time
import threading
import re
from utils import normalize_url, print_banner, C
from scanner import detect_version, get_vulns, get_domain_info, get_plugins, get_users

class Spinner:
    def __init__(self, message="Loading..."):
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.message = message
        self.running = False
        self.thread = None

    def spin(self):
        i = 0
        while self.running:
            sys.stdout.write(f"\r{C.CYAN}[{self.spinner[i]}]{C.RESET} {self.message}")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % len(self.spinner)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")

def print_info_box(version, source, domain_info):
    info_lines = [
        f"{C.GREEN}WordPress Version:{C.RESET} {version} (from {source})",
        f"{C.GREEN}Domain IP        :{C.RESET} {domain_info['ip']}",
        f"{C.GREEN}Site Language    :{C.RESET} {domain_info['lang']}",
        f"{C.GREEN}Domain Created   :{C.RESET} {domain_info['created']}"
    ]
    visible_lengths = [len(re.sub(r'\033\[[0-9;]*m', '', text)) for text in info_lines]
    title = "Site Information"
    max_len = max(max(visible_lengths), len(title))
    width = max_len + 4
    print(f"{C.MAGENTA}╔" + "═" * width + "╗")
    left_padding = (width - len(title)) // 2
    right_padding = width - len(title) - left_padding
    print(f"{C.MAGENTA}║{' ' * left_padding}{C.CYAN}{C.BOLD}{title}{C.RESET}{' ' * right_padding}{C.MAGENTA}║")
    print(f"{C.MAGENTA}╠" + "═" * width + "╣")
    for i, text in enumerate(info_lines):
        padding = width - visible_lengths[i] - 2
        print(f"{C.MAGENTA}║ {text}{' ' * padding} {C.MAGENTA}║")
    print(f"{C.MAGENTA}╚" + "═" * width + "╝\n")

def print_vulns(version):
    vulns = get_vulns(version)
    if not vulns: return
    if 'error' in vulns[0] or 'info' in vulns[0]:
        msg = vulns[0].get('error') or vulns[0].get('info')
        print(f"{C.RED}[!] {msg}{C.RESET}\n")
        return
    display_vulns = vulns[:15]
    total_vulns = len(vulns)
    table_data = []
    for v in display_vulns:
        name = v.get('name', 'Unknown')
        if name == version or not name or len(name) < 3: name = "Core Vulnerability"
        cve = "N/A"
        if v.get('source') and len(v['source']) > 0: cve = v['source'][0].get('id', 'N/A')
        severity = "UNKNOWN"
        cvss_score = "0.0"
        if v.get('impact') and v['impact'].get('cvss3'):
            severity = v['impact']['cvss3'].get('severity', 'unknown').upper()
            cvss_score = v['impact']['cvss3'].get('score', '0.0')
        if severity in ['CRITICAL', 'HIGH']: sev_color = C.RED; icon = "🔴"
        elif severity == 'MEDIUM': sev_color = C.YELLOW; icon = "🟡"
        elif severity == 'LOW': sev_color = C.GREEN; icon = "🟢"
        else: sev_color = C.BLUE; icon = "🔵"
        table_data.append({"name": name, "cve": cve, "score": cvss_score, "severity": severity, "color": sev_color, "icon": icon})
    title = f"Vulnerabilities (Showing {len(display_vulns)} of {total_vulns})"
    print(f"{C.MAGENTA}╔═════════════════════╦═════════════════════╦════════╦═════════════════════╗")
    left_padding = (72 - len(title)) // 2
    right_padding = 72 - len(title) - left_padding
    print(f"{C.MAGENTA}║{' ' * left_padding}{C.CYAN}{C.BOLD}{title}{C.RESET}{' ' * right_padding}{C.MAGENTA}║")
    print(f"{C.MAGENTA}╠═════════════════════╬═════════════════════╬════════╬═════════════════════╣")
    print(f"{C.MAGENTA}║ {C.CYAN}Vulnerability Name  {C.MAGENTA}║ {C.CYAN}CVE ID              {C.MAGENTA}║ {C.CYAN}Score  {C.MAGENTA}║ {C.CYAN}Severity            {C.MAGENTA}║")
    print(f"{C.MAGENTA}╠═════════════════════╬═════════════════════╬════════╬═════════════════════╣")
    for row in table_data:
        name_trunc = row['name'][:19].ljust(19)
        cve_trunc = row['cve'][:19].ljust(19)
        score = str(row['score'])[:6].ljust(6)
        sev_display = f"{row['icon']} {row['severity']}"
        print(f"{C.MAGENTA}║ {name_trunc} {C.MAGENTA}║ {cve_trunc} {C.MAGENTA}║ {C.YELLOW}{score}{C.MAGENTA} ║ {row['color']}{sev_display.ljust(19)}{C.MAGENTA} ║")
    print(f"{C.MAGENTA}╚═════════════════════╩═════════════════════╩════════╩═════════════════════╝\n")
    if total_vulns > 15: print(f"{C.YELLOW}[!] There are {total_vulns - 15} more vulnerabilities not displayed.{C.RESET}\n")

def print_plugins(plugins):
    title = "Detected Plugins"
    if not plugins:
        print(f"{C.MAGENTA}╔" + "═" * 40 + "╗")
        print(f"{C.MAGENTA}║ {C.YELLOW}No plugins detected in page source.     {C.MAGENTA}║")
        print(f"{C.MAGENTA}╚" + "═" * 40 + "╝\n")
        return
    print(f"{C.MAGENTA}╔" + "═" * 40 + "╗")
    left_padding = (40 - len(title)) // 2
    right_padding = 40 - len(title) - left_padding
    print(f"{C.MAGENTA}║{' ' * left_padding}{C.CYAN}{C.BOLD}{title}{C.RESET}{' ' * right_padding}{C.MAGENTA}║")
    print(f"{C.MAGENTA}╠" + "═" * 40 + "╣")
    for p in plugins:
        padding = 40 - len(p) - 2
        print(f"{C.MAGENTA}║ {C.GREEN}{p}{' ' * padding}{C.MAGENTA} ║")
    print(f"{C.MAGENTA}╚" + "═" * 40 + "╝\n")

def print_users(users):
    title = "Enumerated Users"
    print(f"{C.MAGENTA}╔" + "═" * 40 + "╗")
    left_padding = (40 - len(title)) // 2
    right_padding = 40 - len(title) - left_padding
    print(f"{C.MAGENTA}║{' ' * left_padding}{C.CYAN}{C.BOLD}{title}{C.RESET}{' ' * right_padding}{C.MAGENTA}║")
    print(f"{C.MAGENTA}╠" + "═" * 40 + "╣")
    for u in users:
        padding = 40 - len(u) - 2
        print(f"{C.MAGENTA}║ {C.GREEN}{u}{' ' * padding}{C.MAGENTA} ║")
    print(f"{C.MAGENTA}╚" + "═" * 40 + "╝\n")

def run_scan(url):
    base = normalize_url(url)
    spinner = Spinner(f"Scanning {base} ...")
    spinner.start()
    version, source = detect_version(base)
    domain_info = get_domain_info(base)
    plugins = get_plugins(base)
    users = get_users(base)
    spinner.stop()
    
    if version:
        print_info_box(version, source, domain_info)
        print_vulns(version)
    else:
        print(f"{C.RED}[-] Version not detected{C.RESET}")
        print_info_box("Unknown", "N/A", domain_info)
    
    print_plugins(plugins)
    print_users(users)

def cmd_check(url): run_scan(url)
def cmd_info(url): run_scan(url)

if __name__ == '__main__':
    print_banner()
    epilog_text = f"""
{C.CYAN}Examples:{C.RESET}
  python3 wpecon.py check https://example.com
  python3 wpecon.py info https://example.com/wp-admin
"""
    parser = argparse.ArgumentParser(
        description=f"{C.YELLOW}Wpecon Suite - Advanced WordPress Recon Tool{C.RESET}",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest='cmd', title=f"{C.GREEN}Available Commands{C.RESET}")

    p_check = sub.add_parser('check', help='Full scan (Version + Vulnerabilities + Plugins + Users)')
    p_check.add_argument('url', help='Target URL')

    p_info = sub.add_parser('info', help='Version and vulnerabilities only')
    p_info.add_argument('url', help='Target URL')

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
    elif args.cmd == 'check':
        cmd_check(args.url)
    elif args.cmd == 'info':
        cmd_info(args.url)