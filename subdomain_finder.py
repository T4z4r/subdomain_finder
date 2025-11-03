#!/usr/bin/env python3
"""
Subdomain enumeration tool (passive + optional brute-force)
Author: T4z4r (2025)
"""

import argparse
import json
import sys
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


# ----------------------------------------------------------------------
# 1. Passive: Certificate Transparency (crt.sh)
# ----------------------------------------------------------------------
def fetch_crtsh(domain: str) -> set:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        subs = {entry["name_value"].strip().lower() for entry in data}
        # crt.sh sometimes returns *.domain, remove wildcard
        subs = {s.lstrip("*.").replace(f".{domain}", "") for s in subs if s.endswith(domain)}
        return {f"{s}.{domain}" if s else domain for s in subs}
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return set()


# ----------------------------------------------------------------------
# 2. Passive: Google dork (site:*.domain -site:www.domain)
# ----------------------------------------------------------------------
def fetch_google_dork(domain: str, limit: int = 50) -> set:
    subs = set()
    query = f"site:*.{domain} -site:www.{domain}"
    url = "https://www.google.com/search"
    headers = {"User-Agent": "Mozilla/5.0"}
    start = 0
    while len(subs) < limit:
        params = {"q": query, "start": start, "num": 100}
        try:
            r = requests.get(url, params=params, headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select("a[href^='http']"):
                href = a["href"]
                if f".{domain}" in href:
                    # extract subdomain from URL
                    sub = href.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                    if sub.endswith(f".{domain}"):
                        subs.add(sub.lower())
            if "Next" not in r.text:
                break
            start += 100
        except Exception as e:
            print(f"[!] Google dork error: {e}")
            break
    return subs


# ----------------------------------------------------------------------
# 3. Active: DNS brute-force (optional)
# ----------------------------------------------------------------------
def dns_bruteforce(domain: str, wordlist: str, threads: int = 50) -> set:
    import concurrent.futures
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # public resolvers

    subs = set()
    with open(wordlist) as f:
        words = [line.strip() for line in f if line.strip()]

    def check(sub):
        try:
            full = f"{sub}.{domain}"
            answers = resolver.resolve(full, "A")
            if answers:
                return full
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for result in tqdm(executor.map(check, words), total=len(words), desc="Bruteforcing"):
            if result:
                subs.add(result.lower())
    return subs


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Passive + optional active subdomain enumeration")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-b", "--bruteforce", action="store_true", help="Enable DNS brute-force")
    parser.add_argument("-w", "--wordlist", default="subdomains-top1million-5000.txt",
                        help="Wordlist for brute-force (default: top 5000)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-g", "--google", action="store_true", help="Enable Google dork (slow, may be blocked)")

    args = parser.parse_args()
    domain = args.domain.lower().strip(".")

    print(f"[*] Enumerating subdomains for {domain}")

    all_subs = set()

    # 1. crt.sh
    print("[+] Querying crt.sh ...")
    all_subs.update(fetch_crtsh(domain))

    # 2. Google dork
    if args.google:
        print("[+] Running Google dork ...")
        all_subs.update(fetch_google_dork(domain))

    # 3. Brute-force
    if args.bruteforce:
        print("[+] Starting DNS brute-force ...")
        all_subs.update(dns_bruteforce(domain, args.wordlist))

    # Deduplicate & sort
    final = sorted(all_subs)

    # Output
    print("\n=== Found subdomains ===")
    for s in final:
        print(s)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(final, f, indent=2)
        print(f"\n[+] Saved {len(final)} subdomains to {args.output}")

    print(f"\nTotal unique subdomains: {len(final)}")


if __name__ == "__main__":
    # Install dnspython if brute-force is requested
    if "--bruteforce" in sys.argv:
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            print("[!] dnspython not installed. Run: pip install dnspython")
            sys.exit(1)
    main()