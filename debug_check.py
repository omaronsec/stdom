import sys
from curl_cffi import requests
import re, json

cookie_file = sys.argv[1] if len(sys.argv) > 1 else "cookie.txt"
cookies = {}
with open(cookie_file) as f:
    for line in f:
        line = line.strip()
        if "=" in line:
            k, _, v = line.partition("=")
            cookies[k.strip()] = v.strip()

cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Cookie": cookie_str,
    "X-Nextjs-Data": "1",
    "Accept": "*/*",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
})

BUILD = "5ff164b8"

# Test 1: .br SOA search
print("=== TEST: SOA .br ===")
url = f"https://securitytrails.com/_next/data/{BUILD}/list/email/domainadmins.abbvie.com.json?page=1&search=.br&email=domainadmins.abbvie.com"
session.headers.update({"Referer": "https://securitytrails.com/list/email/domainadmins.abbvie.com?search=.br"})
r = session.get(url, impersonate="chrome120", timeout=15, verify=False)
print(f"Status: {r.status_code}")
try:
    d = r.json()
    data = d["pageProps"]["serverResponse"]["data"]
    print(f"Records: {len(data.get('records', []))}")
    print(f"Total: {data.get('total', 0)}")
    print(f"Meta: {data.get('meta', {})}")
except Exception as e:
    print(f"Parse error: {e}")
    print(f"Raw (first 300): {r.text[:300]}")

# Test 2: NS lookup
print("\n=== TEST: NS abbviedns ===")
url2 = f"https://securitytrails.com/_next/data/{BUILD}/list/ns/ns1.abbviedns.com.json?page=1&ns=ns1.abbviedns.com"
session.headers.update({"Referer": "https://securitytrails.com/list/ns/ns1.abbviedns.com"})
r2 = session.get(url2, impersonate="chrome120", timeout=15, verify=False)
print(f"Status: {r2.status_code}")
try:
    d2 = r2.json()
    data2 = d2["pageProps"]["serverResponse"]["data"]
    print(f"Records: {len(data2.get('records', []))}")
    print(f"Total: {data2.get('total', 0)}")
except Exception as e:
    print(f"Parse error: {e}")
    print(f"Raw (first 300): {r2.text[:300]}")
