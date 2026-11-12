import requests
import whois
import socket
import re
from utils import extract_version

def detect_version(base_url):
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 Wpecon/1.0'})

    try:
        r = session.get(f"{base_url}/readme.html", timeout=8)
        if r.status_code == 200:
            v = extract_version(r.text, 'readme')
            if v: return v, 'readme.html'
    except: pass

    try:
        r = session.get(f"{base_url}/feed/", timeout=8)
        if r.status_code == 200:
            v = extract_version(r.text, 'feed')
            if v: return v, '/feed/'
    except: pass

    try:
        r = session.get(base_url, timeout=8)
        v = extract_version(r.text, 'meta')
        if v: return v, 'meta generator'
    except: pass

    return None, None

def get_vulns(version):
    if not version:
        return [{"error": "Unknown version, cannot fetch vulnerabilities"}]

    try:
        url = f"https://www.wpvulnerability.net/core/{version}/"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            vulns_data = data.get('data', {}).get('vulnerability', [])
            if not vulns_data:
                return [{"info": "No known vulnerabilities for this version"}]
            return vulns_data
        return [{"error": f"API Error: {r.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]

def get_domain_info(base_url):
    domain = base_url.replace('https://', '').replace('http://', '').split('/')[0]
    info = {"ip": "N/A", "lang": "N/A", "created": "N/A"}
    
    try:
        info["ip"] = socket.gethostbyname(domain)
    except:
        pass

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            info["created"] = creation_date.strftime('%Y-%m-%d')
    except:
        pass

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(base_url, headers=headers, timeout=8)
        html_lang = re.search(r'<html[^>]*lang=["\']([a-zA-Z-]+)["\']', r.text, re.I)
        if html_lang:
            info["lang"] = html_lang.group(1).upper()
        else:
            info["lang"] = "Unknown"
    except:
        pass
        
    return info

def get_plugins(base_url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(base_url, headers=headers, timeout=8)
        matches = re.findall(r'wp-content/plugins/([^/]+)/', r.text)
        plugins = list(set(matches))
        return plugins if plugins else []
    except:
        return []

def get_users(base_url):
    try:
        r = requests.get(f"{base_url}/wp-json/wp/v2/users", timeout=8)
        if r.status_code == 200:
            users = r.json()
            result = []
            for u in users:
                result.append(f"{u.get('name', 'N/A')} (ID: {u.get('id', 'N/A')})")
            return result if result else ["No users found"]
        return ["Endpoint not accessible"]
    except:
        return ["Error fetching users"]