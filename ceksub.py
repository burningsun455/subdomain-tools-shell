#!/usr/bin/env python3
"""
subdomain_checker.py
Cek subdomain akurat: deteksi wildcard DNS, resolve DNS, cek HTTP/HTTPS concurrently.
Usage:
  python subdomain_checker.py target.com wordlist.txt
If wordlist omitted, uses built-in small list.
Outputs results.csv
"""

import sys
import asyncio
import random
import string
import csv
import socket
from typing import List, Dict, Optional, Tuple
import dns.resolver
import aiohttp
from bs4 import BeautifulSoup
import hashlib

# ---------- Config ----------
DNS_TIMEOUT = 3.0
HTTP_TIMEOUT = 8.0
CONCURRENCY = 40
WILDCARD_TESTS = 3  # number of random subdomains to test for wildcard
# ----------------------------

resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT
resolver.timeout = DNS_TIMEOUT

default_wordlist = [
    "www","api","dev","test","mail","smtp","webmail","admin","portal","staging",
    "beta","m","shop","static","cdn","assets","blog","git","vpn","imap","pop"
]


def random_token(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def resolve_dns(name: str) -> Dict[str, List[str]]:
    """Resolve A, AAAA, CNAME for name. Returns dict with lists (may be empty)."""
    out = {"A": [], "AAAA": [], "CNAME": []}
    try:
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                answers = resolver.resolve(name, rtype)
                for r in answers:
                    out[rtype].append(r.to_text())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
    except Exception:
        pass
    return out


async def fetch_http(session: aiohttp.ClientSession, url: str) -> Tuple[int, Dict[str,str], str]:
    """Fetch URL, return (status, headers, body-hash) - small body read to compute signature."""
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True) as resp:
            text = await resp.text(errors='ignore')
            # compute small signature: status + body-hash + length
            body_hash = hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()[:16]
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, f"{body_hash}:{len(text)}"
    except asyncio.TimeoutError:
        return -1, {}, "TIMEOUT"
    except aiohttp.ClientConnectorError:
        return -2, {}, "NX"
    except Exception:
        return -3, {}, "ERR"


async def check_subdomain(name: str, wildcard_signatures: Optional[Dict] = None, semaphore: asyncio.Semaphore = None) -> Dict:
    """Check DNS and HTTP for a subdomain name. Returns result dict."""
    if semaphore is None:
        semaphore = asyncio.Semaphore(CONCURRENCY)
    async with semaphore:
        result = {
            "subdomain": name,
            "resolved_A": [],
            "resolved_AAAA": [],
            "resolved_CNAME": [],
            "http_status": {"http": None, "https": None},
            "http_sig": {"http": None, "https": None},
            "server_header": {"http": None, "https": None},
            "title": {"http": None, "https": None},
            "possible_wildcard": False
        }

        # DNS (blocking sync, fast enough). If you want async DNS, swap to aiodns.
        dnsinfo = resolve_dns(name)
        result["resolved_A"] = dnsinfo.get("A", [])
        result["resolved_AAAA"] = dnsinfo.get("AAAA", [])
        result["resolved_CNAME"] = dnsinfo.get("CNAME", [])

        # If nothing resolved, skip HTTP attempts (but sometimes HTTP may still respond via wildcard)
        urls = []
        # try http(s) only if there are DNS answers OR if wildcard_signatures might apply
        if result["resolved_A"] or wildcard_signatures is not None:
            urls = [("http", f"http://{name}"), ("https", f"https://{name}")]
        else:
            # quick check using socket connect as fallback to see if port 80/443 open (rare)
            try:
                socket.gethostbyname(name)
                urls = [("http", f"http://{name}"), ("https", f"https://{name}")]
            except Exception:
                urls = []

        async with aiohttp.ClientSession() as session:
            for proto, url in urls:
                status, headers, sig = await fetch_http(session, url)
                result["http_status"][proto] = status
                result["http_sig"][proto] = sig
                result["server_header"][proto] = headers.get("server") if headers else None

                # try extract title if body retrieved
                if status > 0 and sig not in ("TIMEOUT", "NX", "ERR"):
                    # get body again quickly (could optimize by returning body from fetch_http)
                    try:
                        async with session.get(url, timeout=HTTP_TIMEOUT) as resp2:
                            txt = await resp2.text(errors='ignore')
                            soup = BeautifulSoup(txt, "html.parser")
                            title = soup.title.string.strip() if soup.title and soup.title.string else None
                            result["title"][proto] = title
                    except Exception:
                        pass

        # Wildcard detection: if wildcard_signatures provided (dict with 'ips' & 'sigs'),
        # mark possible_wildcard True if this subdomain resolves to the same IPs or has same signature.
        if wildcard_signatures:
            # check IP overlap
            ips = set(result["resolved_A"] + result["resolved_AAAA"])
            if ips and ips == set(wildcard_signatures.get("ips", [])):
                result["possible_wildcard"] = True
            # check HTTP signature match (any)
            for p in ("http", "https"):
                sig = result["http_sig"].get(p)
                if sig and sig == wildcard_signatures.get("sig"):
                    result["possible_wildcard"] = True

        return result


def detect_wildcard(domain: str) -> Optional[Dict]:
    """
    Detect wildcard DNS or wildcard hosting by querying random subdomains.
    Returns dict with 'ips' and 'sig' if wildcard likely, else None.
    """
    ips_collected = []
    sigs = []
    for _ in range(WILDCARD_TESTS):
        rand_sub = f"{random_token(10)}.{domain}"
        dnsinfo = resolve_dns(rand_sub)
        ips = dnsinfo.get("A", []) + dnsinfo.get("AAAA", [])
        ips_collected.append(tuple(sorted(ips)))
        # try HTTP quickly (sync fallback)
        sig = None
        try:
            # attempt basic socket resolve -> if resolves, attempt http signature via requests-like minimal fetch
            addr = None
            if ips:
                addr = ips[0]
            else:
                # if dns didn't resolve, skip
                addr = None
            if addr is not None:
                # attempt small HTTP GET using socket (very minimal) - but to keep simple: use aiohttp sync by running loop.
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                async def just_fetch(url):
                    async with aiohttp.ClientSession() as s:
                        try:
                            async with s.get(url, timeout=HTTP_TIMEOUT) as r:
                                txt = await r.text(errors='ignore')
                                return hashlib.sha256(txt.encode('utf-8', errors='ignore')).hexdigest()[:16] + ":" + str(len(txt))
                        except Exception:
                            return None
                try:
                    sig = loop.run_until_complete(just_fetch(f"http://{rand_sub}"))
                finally:
                    loop.run_until_complete(asyncio.sleep(0))
                    loop.close()
        except Exception:
            sig = None
        sigs.append(sig)

    # if all ips tuples are equal and not empty -> likely wildcard DNS
    unique_ip_sets = set(ips_collected)
    unique_sigs = set(sigs)
    if len(unique_ip_sets) == 1 and list(unique_ip_sets)[0] != ():
        return {"ips": list(list(unique_ip_sets)[0]), "sig": next(iter(unique_sigs)) if unique_sigs else None}
    # if all signatures equal and not None -> likely wildcard hosting
    if len(unique_sigs) == 1 and next(iter(unique_sigs)) is not None:
        return {"ips": [], "sig": next(iter(unique_sigs))}
    return None


async def run_checks(domain: str, candidates: List[str]):
    sem = asyncio.Semaphore(CONCURRENCY)
    # detect wildcard first
    print(f"[+] Detecting wildcard for {domain} ...")
    wildcard = detect_wildcard(domain)
    if wildcard:
        print(f"[!] Wildcard likely detected: {wildcard}")
    else:
        print("[+] No wildcard detected.")

    tasks = []
    for sub in candidates:
        fqdn = f"{sub}.{domain}"
        tasks.append(asyncio.create_task(check_subdomain(fqdn, wildcard_signatures=wildcard, semaphore=sem)))

    results = await asyncio.gather(*tasks)

    # filter out those likely wildcard and with no useful evidence
    final = []
    for r in results:
        # heuristics: if no DNS and no http -> ignore
        has_dns = bool(r["resolved_A"] or r["resolved_AAAA"] or r["resolved_CNAME"])
        has_http = any((r["http_status"].get("http") or r["http_status"].get("https")) and r["http_status"].get("http") not in (-1,-2,-3) for _ in [0])
        # if possible wildcard, still include but mark
        if has_dns or has_http:
            final.append(r)

    # write CSV
    csvfile = "results.csv"
    with open(csvfile, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        header = ["subdomain", "A", "AAAA", "CNAME", "http_status", "https_status", "http_sig", "https_sig", "server_http", "server_https", "title_http", "title_https", "possible_wildcard"]
        writer.writerow(header)
        for r in final:
            writer.writerow([
                r["subdomain"],
                ";".join(r["resolved_A"]),
                ";".join(r["resolved_AAAA"]),
                ";".join(r["resolved_CNAME"]),
                r["http_status"].get("http"),
                r["http_status"].get("https"),
                r["http_sig"].get("http"),
                r["http_sig"].get("https"),
                r["server_header"].get("http"),
                r["server_header"].get("https"),
                r["title"].get("http"),
                r["title"].get("https"),
                r["possible_wildcard"]
            ])

    print(f"[+] Done. Results saved to {csvfile}. Found {len(final)} candidate(s).")
    # pretty print some important ones
    for r in final:
        print(f"{r['subdomain']} - A:{r['resolved_A']} CNAME:{r['resolved_CNAME']} | http:{r['http_status']} wildcard:{r['possible_wildcard']}")


def load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return default_wordlist
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"Could not load wordlist {path}: {e}. Using default list.")
        return default_wordlist


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomain_checker.py domain.tld [wordlist.txt]")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    wordlist = load_wordlist(sys.argv[2] if len(sys.argv) > 2 else None)
    # if user passed a file but wants all common prefixes with deeper heuristics, user can provide a bigger list
    print(f"Target: {domain}, candidates: {len(wordlist)}")
    asyncio.run(run_checks(domain, wordlist))
