#!/usr/bin/env python3
import json
import re
import sys
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
MAX_CT_RESULTS = 150
MAX_DISCOVERY_PROBES = 60


def normalize(url: str) -> str:
    return (url or "").strip().rstrip("/")


def dedupe(items):
    result = []
    seen = set()
    for item in items:
        item = normalize(item)
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def hostname(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def clean_host(host: str) -> str:
    host = (host or "").lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def first_label(host: str) -> str:
    host = clean_host(host)
    return host.split(".")[0] if host else ""


def clean_cert_name(name: str):
    name = (name or "").strip().lower().replace("*.", "")
    if not name or "/" in name or " " in name:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", name):
        return None
    return name


def html_matches(text: str, host: str, provider: dict) -> bool:
    markers = [
        m.lower().strip()
        for m in provider.get("match_any", [])
        if m and m.strip()
    ]
    haystack = (host + "\n" + (text or "")[:300000]).lower()
    return bool(markers) and any(marker in haystack for marker in markers)


def probe(url: str, provider: dict):
    url = normalize(url)
    if not url:
        return None

    attempts = [url]
    if url.startswith("https://"):
        attempts.append("http://" + url[len("https://"):])

    for candidate_url in attempts:
        try:
            response = requests.get(
                candidate_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True,
            )
            if response.status_code >= 400:
                continue

            final = normalize(response.url)
            final_host = hostname(final)

            if html_matches(response.text or "", final_host, provider):
                if final.startswith("http://"):
                    final = "https://" + final[len("http://"):]
                return final

        except requests.RequestException:
            pass

    return None


def ct_discover_same_name(provider: dict):
    base_name = (
        provider.get("base_name")
        or first_label(hostname(provider.get("current", "")))
    ).strip().lower()

    if not base_name:
        return []

    url = f"https://crt.sh/?q={base_name}.%25&output=json"
    found = []
    seen = set()

    try:
        response = requests.get(url, headers=HEADERS, timeout=CT_TIMEOUT)
        if response.status_code != 200:
            return []

        data = response.json()
        if not isinstance(data, list):
            return []

        for row in data[:MAX_CT_RESULTS]:
            raw = row.get("name_value", "")
            for cert_name in str(raw).splitlines():
                domain = clean_cert_name(cert_name)
                if not domain:
                    continue

                # Sicurezza: auto-update soltanto se il nome del sito resta identico
                # e cambia il dominio/TLD. Es.: eurostream.mom -> eurostream.xxx.
                if first_label(domain) != base_name:
                    continue

                if domain not in seen:
                    seen.add(domain)
                    found.append(domain)

    except (requests.RequestException, ValueError):
        return []

    return found


def discovery_candidates(provider: dict):
    current_host = clean_host(hostname(provider.get("current", "")))
    current_suffix = current_host.split(".", 1)[1] if "." in current_host else ""

    domains = ct_discover_same_name(provider)

    def score(domain):
        value = 0
        value -= domain.count(".") * 3
        if current_suffix and domain.endswith("." + current_suffix):
            value += 5
        value -= len(domain) / 100
        return value

    domains.sort(key=score, reverse=True)
    return ["https://" + domain for domain in domains[:MAX_DISCOVERY_PROBES]]


def main():
    config = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
    resolved = []
    changed = False

    for provider in config.get("providers", []):
        known = dedupe(
            [provider.get("current", "")]
            + provider.get("candidates", [])
        )

        winner = None

        # 1) Prova dominio attuale e candidati già conosciuti.
        for candidate in known:
            winner = probe(candidate, provider)
            if winner:
                break

        # 2) Se non funziona, cerca SOLO stesso nome con TLD/dominio differente.
        if not winner:
            print(
                f"[DISCOVERY] {provider['name']}: "
                "domini noti non verificati; cerco stesso nome con altro TLD..."
            )

            for candidate in discovery_candidates(provider):
                print(f"[TRY] {provider['name']}: {candidate}")
                winner = probe(candidate, provider)
                if winner:
                    print(f"[FOUND] {provider['name']}: {winner}")
                    break

        if winner:
            resolved.append(winner)
            old = normalize(provider.get("current", ""))

            if old != winner:
                print(f"[UPDATE] {provider['name']}: {old or '(vuoto)'} -> {winner}")
                provider["current"] = winner
                provider["candidates"] = dedupe(
                    [winner] + provider.get("candidates", [])
                )[:8]
                changed = True
            else:
                print(f"[OK] {provider['name']}: {winner}")

        else:
            # V2.3: non cancellare una sorgente solo perché un singolo check fallisce.
            # Mantiene il dominio corrente nel file live e riprova al giro successivo.
            current = normalize(provider.get("current", ""))
            if current:
                print(
                    f"[KEEP] {provider['name']}: verifica fallita; "
                    f"mantengo {current}"
                )
                resolved.append(current)
            else:
                print(f"[OFFLINE] {provider['name']}: nessun URL configurato")

    OUTPUT_FILE.write_text(
        "\n".join(dedupe(resolved)) + ("\n" if resolved else ""),
        encoding="utf-8"
    )

    if changed:
        PROVIDERS_FILE.write_text(
            json.dumps(config, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
