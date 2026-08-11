# cybertools

Defensive **OSINT / cybersecurity exposure-audit toolkit** for authorized investigations, asset inventory, and self-auditing.

> ⚠️ Use only on systems, domains, and identities you own or have explicit permission to assess. The project does not attempt to recover credentials, bypass access controls, collect private data, or prove a real-world identity from a username alone.

## Features

- `domain` — DNS resolution, HTTP reachability, common security headers, and `robots.txt` metadata.
- `tls` — public TLS version, cipher, certificate subject/issuer, validity dates, and SANs.
- `headers` — inspect public HTTP response headers for an authorized URL.
- `username` — check whether a public profile URL appears to exist on a small fixed set of services. This is a presence check, **not de-anonymization or identity proof**.

## Usage

```bash
python3 cybertools.py domain example.com
python3 cybertools.py tls example.com
python3 cybertools.py headers https://example.com
python3 cybertools.py username example_user
```

All commands emit JSON so the output can be piped into other defensive tooling.

## Roadmap

- RDAP/WHOIS domain metadata with rate limits
- DNS record inventory (A/AAAA/MX/NS/TXT/CNAME)
- certificate-transparency discovery for assets owned by the operator
- breach-notification integration using an API key, limited to authorized/self-owned accounts
- JSON/CSV report export
- unit tests and CI

## Safety boundary

This repository is intentionally focused on **defensive OSINT**. It should not be extended with credential attacks, doxxing, stalking, covert tracking, private-data aggregation, or techniques intended to deanonymize a private person without authorization.
