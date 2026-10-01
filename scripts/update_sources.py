#!/usr/bin/env python3
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS_FILE = ROOT / "providers.json"
OUTPUT_FILE = ROOT / "tairon_sources.txt"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"
    )
}
TIMEOUT = 12
CT_TIMEOUT = 20
MAX_CT_RESULTS_PER_QUERY = 80
MAX_DISCOVERY_PROBES = 40


def normalize(url: str) -> str:
    return (url or "").strip().rstrip("/")


def dedupe(items):
    out, seen = [], set()
    for item in items:
        item = normalize(item)
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def hostname(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def html_matches(text: str, host: str, provider: dict) -> bool:
    markers = [m.lower().strip() for m in provider.get("match_any", []) if m and m.strip()]
    hay = (host + "\n" + (text or "")[:300000]).lower()
    return bool(markers) and any(marker in hay for marker in markers)


def probe(url: str, provider: dict):
    url = normalize(url)
    if not url:
        return None

    for candidate_url in (url, url.replace("https://", "http://", 1)):
        try:
            r = requests.get(
                candidate_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True,
            )
            if r.status_code >= 400:
                continue

            final = normalize(r.url)
            host = hostname(final)

            if html_matches(r.text or "", host, provider):
                if final.startswith("http://"):
                    final = "https://" + final[len("http://"):]
                return final
        except requests.RequestException:
            pass

    return None


def clean_cert_name(name: str):
    name = (name or "").strip().lower()
    name = name.replace("*.", "")
    if not name or "/" in name or " " in name:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", name):
        return None
    return name


def ct_discover_domains(provider: dict):
    found = []
    seen = set()

    queries = provider.get("ct_queries", [])
    for query in queries:
        query = (query or "").strip().lower()
        if not query:
            continue

        try:
            # crt.sh Certificate Transparency search.
            # %25 = wildcard %, so we look for certificates containing the provider token.
            url = f"https://crt.sh/?q=%25{query}%25&output=json"
            r = requests.get(url, headers=HEADERS, timeout=CT_TIMEOUT)
            if r.status_code != 200:
                continue

            data = r.json()
            if not isinstance(data, list):
                continue

            for row in data[:MAX_CT_RESULTS_PER_QUERY]:
                raw = row.get("name_value", "")
                for cert_name in str(raw).splitlines():
                    domain = clean_cert_name(cert_name)
                    if not domain:
                        continue

                    # Avoid overly broad matches. At least one configured CT token
                    # must be present in the hostname.
                    if not any(q in domain.replace("-", "") for q in queries if q):
                        continue

                    if domain not in seen:
                        seen.add(domain)
                        found.append(domain)

        except (requests.RequestException, ValueError):
            continue

        time.sleep(0.4)

    return found


def discovery_candidates(provider: dict):
    current = hostname(provider.get("current", ""))
    configured = [hostname(x) for x in provider.get("candidates", []) if x]

    domains = ct_discover_domains(provider)

    def score(domain):
        # Prefer domains that look closest to known provider identity.
        s = 0
        compact = domain.replace("-", "")
        for q in provider.get("ct_queries", []):
            if q and q in compact:
                s += 20
        if current and domain.split(".")[0] == current.split(".")[0]:
            s += 30
        for known in configured:
            if known and domain.split(".")[0] == known.split(".")[0]:
                s += 20
        # Prefer shorter, cleaner hostnames.
        s -= domain.count(".") * 2
        s -= len(domain) / 100
        return s

    domains.sort(key=score, reverse=True)
    return ["https://" + d for d in domains[:MAX_DISCOVERY_PROBES]]


def main():
    cfg = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
    resolved = []
    changed = False

    for p in cfg.get("providers", []):
        known = dedupe([p.get("current", "")] + p.get("candidates", []))
        winner = None

        # 1) Fast path: current + known candidates.
        for candidate in known:
            winner = probe(candidate, p)
            if winner:
                break

        # 2) If everything known fails, discover new domains from Certificate Transparency.
        if not winner:
            print(f"[DISCOVERY] {p['name']}: domini noti non validi, cerco nuovi certificati...")
            for candidate in discovery_candidates(p):
                print(f"[TRY] {p['name']}: {candidate}")
                winner = probe(candidate, p)
                if winner:
                    print(f"[FOUND] {p['name']}: {winner}")
                    break

        if winner:
            resolved.append(winner)
            old = normalize(p.get("current", ""))

            if old != winner:
                print(f"[UPDATE] {p['name']}: {old or '(vuoto)'} -> {winner}")
                p["current"] = winner

                candidates = dedupe([winner] + p.get("candidates", []))
                p["candidates"] = candidates[:8]
                changed = True
            else:
                print(f"[OK] {p['name']}: {winner}")
        else:
            old = normalize(p.get("current", ""))
            if old:
                # Safety: do NOT replace a known URL with an unverified one.
                # Keep old value in config, but omit it from live list if unreachable.
                print(f"[OFFLINE] {p['name']}: nessun dominio verificato trovato; non pubblico {old}")
            else:
                print(f"[OFFLINE] {p['name']}: nessun dominio verificato trovato")

    # Only publish domains verified in this run.
    OUTPUT_FILE.write_text(
        "\n".join(dedupe(resolved)) + ("\n" if resolved else ""),
        encoding="utf-8"
    )

    if changed:
        PROVIDERS_FILE.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
