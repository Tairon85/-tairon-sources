#!/usr/bin/env python3
import json
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


def looks_valid(response, provider):
    if response.status_code >= 400:
        return False

    final_url = normalize(response.url)
    host = urlparse(final_url).netloc.lower()
    text = (response.text or "")[:250000].lower()

    markers = [
        marker.lower().strip()
        for marker in provider.get("match_any", [])
        if marker and marker.strip()
    ]

    if not markers:
        return True

    return any(marker in host or marker in text for marker in markers)


def probe(url, provider):
    try:
        response = requests.get(
            normalize(url),
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        if looks_valid(response, provider):
            return normalize(response.url)
    except requests.RequestException as exc:
        print(f"[ERROR] {url}: {exc}")

    return None


def main():
    config = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
    resolved = []
    changed = False

    for provider in config.get("providers", []):
        candidates = dedupe(
            [provider.get("current", "")]
            + provider.get("candidates", [])
        )

        winner = None

        for candidate in candidates:
            winner = probe(candidate, provider)
            if winner:
                break

        if winner:
            resolved.append(winner)

            old = normalize(provider.get("current", ""))
            if old != winner:
                print(
                    f"[UPDATE] {provider['name']}: "
                    f"{old or '(vuoto)'} -> {winner}"
                )
                provider["current"] = winner
                changed = True
            else:
                print(f"[OK] {provider['name']}: {winner}")

        else:
            current = normalize(provider.get("current", ""))

            if current:
                print(
                    f"[WARN] {provider['name']}: "
                    f"nessun URL valido trovato, mantengo {current}"
                )
                resolved.append(current)
            else:
                print(
                    f"[WARN] {provider['name']}: "
                    "nessun URL configurato o valido"
                )

    OUTPUT_FILE.write_text(
        "\n".join(dedupe(resolved)) + "\n",
        encoding="utf-8",
    )

    if changed:
        PROVIDERS_FILE.write_text(
            json.dumps(config, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
