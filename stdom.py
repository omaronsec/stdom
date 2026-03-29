#!/usr/bin/env python3
"""
stdom.py - SecurityTrails Domain Recon Tool
Usage: python3 stdom.py -t target.com -s cookie.txt -m all -o output.txt [-tlds /path/to/tlds.txt]
"""

import sys, os, re, json, time, argparse
from curl_cffi import requests

# ─── DEFAULT TLD FILE ────────────────────────────────────────────────────────
DEFAULT_TLDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "countries_tld.txt")
BASE_URL     = "https://securitytrails.com"
SHARED_THRESHOLD = 50000  # NS returning more than this = likely shared provider

# ─── COLORS ──────────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
BOLD="\033[1m"
RST= "\033[0m"

def banner():
    print(f"""
{C}{BOLD}  ██████╗████████╗██████╗  ██████╗ ███╗   ███╗
 ██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗████╗ ████║
 ╚█████╗    ██║   ██║  ██║██║   ██║██╔████╔██║
  ╚═══██╗   ██║   ██║  ██║██║   ██║██║╚██╔╝██║
 ██████╔╝   ██║   ██████╔╝╚██████╔╝██║ ╚═╝ ██║
 ╚═════╝    ╚═╝   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝{RST}
{DIM}  SecurityTrails Domain Recon  |  @omaronsec{RST}
""")

def info(msg):  print(f"  {B}[*]{RST} {msg}")
def ok(msg):    print(f"  {G}[✓]{RST} {msg}")
def warn(msg):  print(f"  {Y}[!]{RST} {msg}")
def err(msg):   print(f"  {R}[✗]{RST} {msg}")
def found(msg): print(f"  {G}[+]{RST} {BOLD}{msg}{RST}")
def section(title):
    print(f"\n{C}{'─'*55}{RST}")
    print(f"{C}  {title}{RST}")
    print(f"{C}{'─'*55}{RST}")

# ─── LOAD COOKIE FILE ────────────────────────────────────────────────────────
def load_cookies(path):
    cookies = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                cookies[key.strip()] = val.strip()
    except FileNotFoundError:
        err(f"Cookie file not found: {path}")
        sys.exit(1)

    missing = [k for k in ["cf_clearance", "SecurityTrails"] if k not in cookies]
    if missing:
        err(f"Missing required cookie(s): {', '.join(missing)}")
        err("Cookie file must contain: cf_clearance=xxx and SecurityTrails=xxx")
        sys.exit(1)

    return cookies

def build_cookie_header(cookies):
    static = {
        "securitytrails_asn_preload": "1",
        "X-ST-Client": "web",
    }
    merged = {**static, **cookies}
    return "; ".join(f"{k}={v}" for k, v in merged.items())

# ─── SESSION ─────────────────────────────────────────────────────────────────
def make_session(cookie_str):
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en-GB;q=0.9,en;q=0.8",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Cookie": cookie_str,
    })
    return s

# ─── BUILD ID DETECTION ──────────────────────────────────────────────────────
def get_build_id(session):
    info("Detecting SecurityTrails build ID...")
    try:
        r = session.get(f"{BASE_URL}/app/account", impersonate="chrome120",
                        timeout=15, verify=False, allow_redirects=True)

        if "Just a moment" in r.text or "cf-browser-verification" in r.text:
            err("Cloudflare blocked the request!")
            warn("Your cf_clearance cookie is tied to the device/IP used to log in.")
            warn("Run this script on the same machine you used to log in to SecurityTrails.")
            sys.exit(1)

        match = re.search(r'"buildId"\s*:\s*"([a-f0-9]+)"', r.text)
        if match:
            build_id = match.group(1)
            ok(f"Build ID detected: {C}{build_id}{RST}")
            return build_id
        else:
            err("Could not find buildId in response.")
            sys.exit(1)
    except Exception as e:
        err(f"Failed to fetch build ID: {e}")
        sys.exit(1)

# ─── SESSION CHECK ───────────────────────────────────────────────────────────
def check_session(session, build_id):
    info("Validating session...")
    try:
        url = f"{BASE_URL}/_next/data/{build_id}/domain/google.com/dns.json?domain=google.com"
        r = session.get(url, impersonate="chrome120", timeout=15, verify=False)

        if "Just a moment" in r.text or "cf-browser-verification" in r.text:
            err("Cloudflare blocked — cf_clearance cookie doesn't match this machine/IP.")
            warn("Run this script from the same machine/browser used to log in.")
            sys.exit(1)

        d = r.json()
        user = d.get("pageProps", {}).get("user", {})
        email = user.get("email", "")
        plan  = user.get("packageCode", "")
        name  = user.get("name", "")

        if not email:
            err("Session invalid — not authenticated. Update your SecurityTrails cookie.")
            sys.exit(1)

        ok(f"Session valid  →  {G}{name}{RST} ({email})  |  Plan: {C}{plan}{RST}")
        return True

    except Exception as e:
        err(f"Session check failed: {e}")
        sys.exit(1)

# ─── TARGET INFO ─────────────────────────────────────────────────────────────
def get_target_info(session, build_id, target):
    section(f"Target Intelligence: {target}")
    url = f"{BASE_URL}/_next/data/{build_id}/domain/{target}/dns.json?domain={target}"
    session.headers.update({"Referer": f"{BASE_URL}/domain/{target}"})

    try:
        r = session.get(url, impersonate="chrome120", timeout=15, verify=False)
        d = r.json()
        dns = d["pageProps"]["dnsData"]["data"]

        result = {"soa_emails": [], "ns_records": [], "raw": dns}

        # SOA
        soa_vals = dns.get("current_dns", {}).get("soa", {}).get("values", [])
        for v in soa_vals:
            email = v.get("email", "")
            if email:
                result["soa_emails"].append(email)
                found(f"SOA Email: {email}")

        # NS
        ns_vals = dns.get("current_dns", {}).get("ns", {}).get("values", [])
        for v in ns_vals:
            ns = v.get("nameserver", "")
            if ns:
                result["ns_records"].append(ns)

        if result["ns_records"]:
            info(f"NS Records ({len(result['ns_records'])}):")
            for ns in result["ns_records"]:
                print(f"    {DIM}→{RST} {ns}")

        # Extra info
        a_vals = dns.get("current_dns", {}).get("a", {}).get("values", [])
        mx_vals = dns.get("current_dns", {}).get("mx", {}).get("values", [])
        subdomain_count = d["pageProps"].get("subdomainsCount", 0)
        is_estimate = d["pageProps"].get("isTotalEstimate", False)

        if a_vals:
            ips = [v.get("ip","") for v in a_vals]
            info(f"A Records: {', '.join(ips)}")
        if mx_vals:
            mxs = [v.get("hostname","") for v in mx_vals]
            info(f"MX Records: {', '.join(mxs[:3])}")

        est = "~" if is_estimate else ""
        info(f"Known subdomains: {C}{est}{subdomain_count:,}{RST}")

        return result

    except Exception as e:
        err(f"Failed to get target info: {e}")
        sys.exit(1)

# ─── NS GROUP LOGIC ──────────────────────────────────────────────────────────
def get_ns_root(ns):
    parts = ns.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else ns

def is_target_related(ns_root, target_keyword):
    return target_keyword.lower() in ns_root.lower()

def select_ns_representatives(ns_records, target, session, build_id):
    """Group NS by root domain, pick one per group, classify as owned vs shared."""
    keyword = target.split(".")[0]
    groups = {}
    for ns in ns_records:
        root = get_ns_root(ns)
        if root not in groups:
            groups[root] = []
        groups[root].append(ns)

    representatives = []
    section("NS Group Analysis")

    for root, members in groups.items():
        rep = members[0]  # pick first from group
        related = is_target_related(root, keyword)

        # Quick count check
        count = get_ns_count(session, build_id, rep)
        time.sleep(0.3)

        if count == "err":
            warn(f"Group [{root}] ({len(members)} NS) → could not check, skipping")
            continue

        if count > SHARED_THRESHOLD:
            tag = f"{Y}shared provider{RST} (~{count:,} domains)"
        elif related:
            tag = f"{G}company-owned{RST} ({count:,} domains)"
        else:
            tag = f"{C}external/custom{RST} ({count:,} domains)"

        print(f"  {DIM}[{root}]{RST} using {rep}  →  {tag}")
        if len(members) > 1:
            print(f"    {DIM}(skipping identical: {', '.join(members[1:])}){RST}")

        representatives.append((rep, count, root))

    return representatives

def get_ns_count(session, build_id, ns):
    url = f"{BASE_URL}/_next/data/{build_id}/list/ns/{ns}.json?ns={ns}"
    session.headers.update({"Referer": f"{BASE_URL}/list/ns/{ns}"})
    try:
        r = session.get(url, impersonate="chrome120", timeout=15, verify=False)
        if "Just a moment" in r.text:
            return "err"
        d = r.json()
        return d["pageProps"]["serverResponse"]["data"].get("total", 0)
    except:
        return "err"

# ─── FETCH PAGES ─────────────────────────────────────────────────────────────
def fetch_page(session, url, referer):
    session.headers.update({"X-Nextjs-Data": "1", "Referer": referer})
    try:
        r = session.get(url, impersonate="chrome120", timeout=15, verify=False)
        if "Just a moment" in r.text or "cf-browser-verification" in r.text:
            return None, "cloudflare"
        d = r.json()
        records = d["pageProps"]["serverResponse"]["data"]["records"]
        meta    = d["pageProps"]["serverResponse"]["data"]["meta"]
        return records, meta
    except Exception as e:
        return None, str(e)

def scrape_all_pages(session, build_id, mode, value, tlds, label):
    """Scrape all pages for a given value (SOA email or NS)."""
    all_domains = set()

    if mode == "soa":
        # Iterate all TLDs
        total_tlds = len(tlds)
        hits = 0
        for i, tld in enumerate(tlds, 1):
            url = f"{BASE_URL}/_next/data/{build_id}/list/email/{value}.json?email={value}&search={tld}"
            ref = f"{BASE_URL}/list/email/{value}?search={tld}"
            records, meta = fetch_page(session, url, ref)

            if records is None:
                if meta == "cloudflare":
                    err(f"Cloudflare blocked on TLD {tld}. Session expired.")
                    warn("Run from the machine used to log in to SecurityTrails.")
                    break
                continue

            if not records:
                continue

            max_page = meta.get("max_page", 1) if isinstance(meta, dict) else 1
            total    = meta.get("total", len(records)) if isinstance(meta, dict) else len(records)
            hostnames = [r["hostname"] for r in records if "hostname" in r]
            all_domains.update(hostnames)
            hits += total
            print(f"  {DIM}[{i}/{total_tlds}]{RST} {tld:<12} {G}+{total}{RST} domains  "
                  f"{DIM}({len(all_domains)} total){RST}")

            for page in range(2, max_page + 1):
                url_p = f"{BASE_URL}/_next/data/{build_id}/list/email/{value}.json?email={value}&search={tld}&page={page}"
                recs_p, meta_p = fetch_page(session, url_p, ref)
                if recs_p:
                    h = [r["hostname"] for r in recs_p if "hostname" in r]
                    all_domains.update(h)
                time.sleep(0.4)

            time.sleep(0.35)

    elif mode == "ns":
        url = f"{BASE_URL}/_next/data/{build_id}/list/ns/{value}.json?ns={value}"
        ref = f"{BASE_URL}/list/ns/{value}"
        records, meta = fetch_page(session, url, ref)

        if records is None:
            if meta == "cloudflare":
                err("Cloudflare blocked.")
            return all_domains

        if not records:
            return all_domains

        max_page = meta.get("max_page", 1) if isinstance(meta, dict) else 1
        total    = meta.get("total", len(records)) if isinstance(meta, dict) else len(records)

        info(f"{label}: {C}{total:,}{RST} domains ({max_page} pages)")
        hostnames = [r["hostname"] for r in records if "hostname" in r]
        all_domains.update(hostnames)

        for page in range(2, max_page + 1):
            url_p = f"{BASE_URL}/_next/data/{build_id}/list/ns/{value}.json?ns={value}&page={page}"
            recs_p, _ = fetch_page(session, url_p, ref)
            if recs_p:
                all_domains.update(r["hostname"] for r in recs_p if "hostname" in r)
            print(f"  {DIM}page {page}/{max_page} → {len(all_domains)} collected{RST}")
            time.sleep(0.4)

    return all_domains

# ─── MAIN ────────────────────────────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SecurityTrails Domain Recon Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t",      required=True,  metavar="domain",      help="Target domain (e.g. abbvie.com)")
    parser.add_argument("-s",      required=True,  metavar="cookie.txt",  help="Cookie file with cf_clearance and SecurityTrails")
    parser.add_argument("-m",      required=True,  metavar="mode",        help="Mode: soa | ns | all",
                        choices=["soa","ns","all"])
    parser.add_argument("-o",      required=True,  metavar="output.txt",  help="Output file path")
    parser.add_argument("-tlds",   required=False, metavar="tlds.txt",    help="TLD list file (default: countries_tld.txt)")

    args = parser.parse_args()

    target   = args.t.lower().strip().lstrip(".")
    out_file = args.o
    mode     = args.m
    tlds_file = args.tlds if args.tlds else DEFAULT_TLDS

    # Load TLDs
    if not os.path.exists(tlds_file):
        err(f"TLD file not found: {tlds_file}")
        sys.exit(1)
    with open(tlds_file) as f:
        tlds = [l.strip() for l in f if l.strip() and l.strip().startswith(".")]
    info(f"Loaded {len(tlds)} TLDs from {tlds_file}")

    # Load cookies
    cookies    = load_cookies(args.s)
    cookie_str = build_cookie_header(cookies)
    session    = make_session(cookie_str)

    # Get build ID
    build_id = get_build_id(session)

    # Validate session
    check_session(session, build_id)

    # Get target DNS info
    dns_info = get_target_info(session, build_id, target)

    all_domains = set()

    # ── SOA MODE ──────────────────────────────────────────────────────────────
    if mode in ["soa", "all"]:
        section("SOA Email Search")
        if not dns_info["soa_emails"]:
            warn("No SOA email found for this target.")
        else:
            for email in dns_info["soa_emails"]:
                info(f"Searching by SOA email: {C}{email}{RST}")
                info(f"Iterating {len(tlds)} TLDs...")
                print()
                domains = scrape_all_pages(session, build_id, "soa", email, tlds, email)
                ok(f"SOA [{email}]: {G}{len(domains):,}{RST} unique domains found")
                all_domains.update(domains)

    # ── NS MODE ───────────────────────────────────────────────────────────────
    if mode in ["ns", "all"]:
        section("NS Record Search")
        if not dns_info["ns_records"]:
            warn("No NS records found for this target.")
        else:
            reps = select_ns_representatives(
                dns_info["ns_records"], target, session, build_id)

            print()
            for ns, count, root in reps:
                info(f"Searching by NS: {C}{ns}{RST}")
                domains = scrape_all_pages(session, build_id, "ns", ns, tlds, ns)
                ok(f"NS [{ns}]: {G}{len(domains):,}{RST} unique domains found")
                all_domains.update(domains)

    # ── FINAL SAVE ────────────────────────────────────────────────────────────
    section("Results")

    # Load existing file if exists (merge)
    existing = set()
    if os.path.exists(out_file):
        with open(out_file) as f:
            existing = set(l.strip() for l in f if l.strip())
        info(f"Merging with existing {len(existing):,} domains in {out_file}")

    final = sorted(all_domains | existing)

    with open(out_file, "w") as f:
        f.write("\n".join(final) + "\n")

    new_count = len(all_domains - existing)
    ok(f"Total unique domains : {G}{BOLD}{len(final):,}{RST}")
    if existing:
        ok(f"New domains added    : {G}{BOLD}+{new_count:,}{RST}")
    ok(f"Saved to             : {C}{out_file}{RST}")
    print()

if __name__ == "__main__":
    main()
