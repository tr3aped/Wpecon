import re
from urllib.parse import urlparse
import pyfiglet

class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    banner_text = pyfiglet.figlet_format("Wpecon", font="ansi_shadow")
    title = "Wpecon Suite - WordPress Recon"
    author = "@Tr3Ped"
    
    lines = banner_text.rstrip('\n').split('\n')
    max_len = max(len(line) for line in lines)
    width = max_len + 4
    
    print(f"{C.MAGENTA}╔" + "═" * width + "╗")
    
    for line in lines:
        print(f"{C.MAGENTA}║  {C.CYAN}{line.ljust(max_len)}  {C.MAGENTA}║")
        
    print(f"{C.MAGENTA}╠" + "═" * width + "╣")
    
    small_yellow_title = f"\033[3m\033[93m{title}\033[0m"
    left_padding = (width - len(title)) // 2
    right_padding = width - len(title) - left_padding
    print(f"{C.MAGENTA}║{' ' * left_padding}{small_yellow_title}{' ' * right_padding}{C.MAGENTA}║")
    
    author_padding = width - len(author) - 2
    print(f"{C.MAGENTA}║{' ' * author_padding}{author}  {C.MAGENTA}║")
    
    print(f"{C.MAGENTA}╚" + "═" * width + "╝\n")

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def extract_version(html, source):
    patterns = {
        'readme': r'[Vv]ersion\s+([\d.]+)',
        'feed': r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
        'meta': r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)'
    }
    m = re.search(patterns.get(source, ''), html, re.I)
    return m.group(1) if m else None