# stdom — SecurityTrails Domain Recon Tool

A fast recon tool that leverages SecurityTrails web session to enumerate all domains associated with a target via **SOA email** and **NS records** — bypassing the 10K result limit by splitting queries across country TLDs.

---

## How It Works

1. Fetches DNS info for the target domain (SOA email + NS records)
2. Depending on mode:
   - **SOA mode** — searches all domains registered with the target's SOA email, iterating through every TLD in your list
   - **NS mode** — searches all domains pointing to the target's nameservers, groups identical NS records and queries one per group
   - **All mode** — runs both
3. Merges and deduplicates all results into a single output file

> The 10K result limit on SecurityTrails is bypassed by splitting queries per TLD (`.uk`, `.br`, `.de`, etc.) — each query returns its own 10K budget.

---

## Requirements

- Python 3.8+
- `curl_cffi` library

```bash
pip3 install curl_cffi
```

---

## Installation

```bash
git clone https://github.com/omaronsec/stdom.git
cd stdom
pip3 install curl_cffi
```

---

## Usage

```bash
python3 stdom.py -t <target> -s <cookie.txt> -m <mode> -o <output.txt> [-tlds <tlds.txt>]
```

### Arguments

| Flag | Required | Description |
|------|----------|-------------|
| `-t` | Yes | Target domain (e.g. `abbvie.com`) |
| `-s` | Yes | Cookie file path |
| `-m` | Yes | Mode: `soa`, `ns`, or `all` |
| `-o` | Yes | Output file path |
| `-tlds` | No | Custom TLD list file (default: `countries_tld.txt`) |

---

## Cookie File

The tool requires a valid SecurityTrails session. Create a file with two lines:

```
cf_clearance=YOUR_CF_CLEARANCE_VALUE
SecurityTrails=YOUR_SECURITYTRAILS_COOKIE_VALUE
```

### How to get your cookies:
1. Log in to [securitytrails.com](https://securitytrails.com) in Chrome
2. Press `F12` → Network tab
3. Refresh the page
4. Click any request to `securitytrails.com`
5. Copy the `Cookie:` header value
6. Extract `cf_clearance=...` and `SecurityTrails=...` into your cookie file

> **Important:** Run the tool from the **same machine** you used to log in. The `cf_clearance` cookie is tied to your IP and browser fingerprint.

---

## Examples

```bash
# SOA email search only
python3 stdom.py -t abbvie.com -s cookie.txt -m soa -o abbvie.txt

# NS records search only
python3 stdom.py -t abbvie.com -s cookie.txt -m ns -o abbvie.txt

# Full scan (SOA + NS)
python3 stdom.py -t abbvie.com -s cookie.txt -m all -o abbvie.txt

# With custom TLD list
python3 stdom.py -t abbvie.com -s cookie.txt -m all -o abbvie.txt -tlds /path/to/tlds.txt

# Merge results with existing file (re-run appends new findings)
python3 stdom.py -t abbvie.com -s cookie.txt -m soa -o abbvie.txt
```

---

## TLD File

The default `countries_tld.txt` contains 272 country-code TLDs (`.uk`, `.br`, `.jp`, `.de`, etc.).

You can provide your own list with `-tlds`. Format: one TLD per line starting with `.`

```
.com
.net
.org
.uk
.br
.jp
```

---

## Output

The tool saves all discovered domains (one per line, sorted, deduplicated) to your output file. If the output file already exists, new results are merged into it.

---

## NS Group Logic

For targets with multiple nameservers, the tool:
- Groups NS records by root domain (e.g. `ns1.abbviedns.com` and `ns2.abbviedns.com` → same group)
- Queries only **one** per group (they return identical results)
- Shows result count per group so you can identify shared DNS providers vs company-owned NS

---

## Disclaimer

This tool is intended for authorized security research and bug bounty programs only. Only use it against targets you have permission to test.
