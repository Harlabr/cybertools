#!/usr/bin/env python3
"""Defensive OSINT / exposure-audit CLI.

Use only against systems, domains, and identities you own or are authorized to assess.
This toolkit deliberately avoids credential attacks, private-data collection, stalking,
and automated deanonymization of private individuals.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = "cybertools/1.0 (authorized-security-audit)"


def http_get(url: str, timeout: int = 8) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers.items()), r.read(256_000)


def normalize_url(value: str) -> str:
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    p = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def domain_report(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    result: dict = {"domain": domain}
    try:
        result["addresses"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None)})
    except socket.gaierror as e:
        result["dns_error"] = str(e)

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            status, headers, body = http_get(url)
            result[scheme] = {
                "status": status,
                "final_url": url,
                "server": headers.get("Server"),
                "content_type": headers.get("Content-Type"),
                "security_headers": {
                    k: headers.get(k) for k in (
                        "Strict-Transport-Security", "Content-Security-Policy",
                        "X-Content-Type-Options", "X-Frame-Options",
                        "Referrer-Policy", "Permissions-Policy",
                    ) if headers.get(k)
                },
                "body_bytes_sampled": len(body),
            }
            if scheme == "https":
                result[scheme]["robots_txt"] = check_robots(domain)
            break
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            result[f"{scheme}_error"] = str(e)
    return result


def check_robots(domain: str) -> dict:
    try:
        status, headers, body = http_get(f"https://{domain}/robots.txt")
        text = body.decode("utf-8", "replace")
        return {"status": status, "disallow_count": len(re.findall(r"^Disallow:", text, re.M)),
                "sitemaps": re.findall(r"^Sitemap:\s*(\S+)", text, re.M | re.I)[:20]}
    except Exception as e:
        return {"error": str(e)}


def tls_report(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            cert = s.getpeercert()
            return {
                "host": host, "port": port,
                "tls_version": s.version(),
                "cipher": s.cipher()[0] if s.cipher() else None,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san": [v for k, vals in cert.get("subjectAltName", []) for v in [vals] if k == "DNS"][:100],
            }


def url_headers(url: str) -> dict:
    url = normalize_url(url)
    status, headers, _ = http_get(url)
    return {"url": url, "status": status, "headers": dict(sorted(headers.items(), key=lambda x: x[0].lower()))}


def username_presence(username: str) -> dict:
    """Check a small fixed set of public profile URLs; no login, scraping, or PII enrichment."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        raise ValueError("invalid username")
    sites = {
        "GitHub": f"https://github.com/{urllib.parse.quote(username)}",
        "GitLab": f"https://gitlab.com/{urllib.parse.quote(username)}",
        "Reddit": f"https://www.reddit.com/user/{urllib.parse.quote(username)}/",
    }
    out = {}
    for name, url in sites.items():
        try:
            status, headers, _ = http_get(url)
            out[name] = {"status": status, "url": url, "reachable": status < 400,
                         "location": headers.get("Location")}
        except Exception as e:
            out[name] = {"url": url, "error": str(e)}
    return {"username": username, "checks": out,
            "note": "Presence is not identity proof; validate ownership independently."}


def main() -> int:
    p = argparse.ArgumentParser(description="Authorized OSINT and cybersecurity exposure-audit toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("domain", help="DNS + HTTP security-header + robots.txt report")
    d.add_argument("domain")
    t = sub.add_parser("tls", help="Inspect the public TLS certificate")
    t.add_argument("host")
    t.add_argument("--port", type=int, default=443)
    h = sub.add_parser("headers", help="Fetch public HTTP response headers")
    h.add_argument("url")
    u = sub.add_parser("username", help="Check public profile URL presence on a few services")
    u.add_argument("username")

    args = p.parse_args()
    try:
        if args.cmd == "domain": out = domain_report(args.domain)
        elif args.cmd == "tls": out = tls_report(args.host, args.port)
        elif args.cmd == "headers": out = url_headers(args.url)
        else: out = username_presence(args.username)
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
