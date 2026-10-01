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


def clean_cert_name(name: str):
    name = (name or "").strip().lower()
    name = name.replace("*.", "")

    if not name:
        return None

    if "/" in name or " " in name:
        return None

    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", name):
        return None

    return name


def get_base_label(domain: str) -> str:
    domain = (domain or "").lower().strip(".")
    if not domain:
        return ""

    # We intentionally compare only the first hostname label.
    # This matches the user's rule:
    # same site name + different TLD = eligible for auto-update.
    return domain.split(".")[0]


def html_matches(text: str, host: str, provider: dict) -> bool:
    markers = [
        m.lower().strip()
        for m in provider.get("match_any", [])
        if m and m.strip()
    ]

    haystack = (
        host + "\n" + (text or "")[:300000]
    ).lower()

    return bool(markers) and any(
        marker in haystack
        for marker in markers
    )


def probe(url: str, provider: dict):
    url = normalize(url)

    if not url:
        return None

    attempts = [url]

    if url.startswith("https://"):
        attempts.append(
            "http://" + url[len("https://"):]
        )

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

            if html_matches(
                response.text or "",
                final_host,
                provider
            ):
                if final.startswith("http://"):
                    final = (
                        "https://"
                        + final[len("http://"):]
                    )

                return final

        except requests.RequestException:
            pass

    return None


def ct_discover_same_name(provider: dict):
    base_name = (
        provider.get("base_name")
        or get_base_label(
            hostname(
                provider.get("current", "")
            )
        )
    ).strip().lower()

    if not base_name:
        return []

    # crt.sh wildcard search: same base name, any public TLD/domain suffix.
    query = f"%.{base_name}.%" if "." in base_name else f"{base_name}.%"

    # More reliable query for exact first label across TLDs:
    # %25 is URL-encoded '%'.
    url = (
        "https://crt.sh/"
        f"?q={base_name}.%25"
        "&output=json"
    )

    found = []
    seen = set()

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=CT_TIMEOUT
        )

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

                # Auto-accept discovery only when the first label remains identical.
                # Example:
                # altadefinizionex.me -> altadefinizionex.off  YES
                # altadefinizionex.me -> newstream.off         NO
                if get_base_label(domain) != base_name:
                    continue

                if domain not in seen:
                    seen.add(domain)
                    found.append(domain)

    except (requests.RequestException, ValueError):
        return []

    return found


def discovery_candidates(provider: dict):
    current_host = hostname(
        provider.get("current", "")
    )

    current_tld = (
        current_host.split(".", 1)[1]
        if "." in current_host
        else ""
    )

    domains = ct_discover_same_name(provider)

    def score(domain):
        score_value = 0

        # Prefer direct two-label domains over deeper subdomains.
        score_value -= domain.count(".") * 3

        # Prefer current suffix only as a weak hint.
        if current_tld and domain.endswith("." + current_tld):
            score_value += 5

        # Slight preference for shorter domains.
        score_value -= len(domain) / 100

        return score_value

    domains.sort(
        key=score,
        reverse=True
    )

    return [
        "https://" + domain
        for domain in domains[:MAX_DISCOVERY_PROBES]
    ]


def main():
    config = json.loads(
        PROVIDERS_FILE.read_text(
            encoding="utf-8"
        )
    )

    resolved = []
    changed = False

    for provider in config.get(
        "providers",
        []
    ):
        known = dedupe(
            [
                provider.get(
                    "current",
                    ""
                )
            ]
            + provider.get(
                "candidates",
                []
            )
        )

        winner = None

        # 1) Current domain + known candidates.
        for candidate in known:
            winner = probe(
                candidate,
                provider
            )

            if winner:
                break

        # 2) If known domains fail, search SAME NAME with a different TLD.
        if not winner:
            print(
                f"[DISCOVERY] "
                f"{provider['name']}: "
                "domini noti non validi; "
                "cerco stesso nome con altro TLD..."
            )

            for candidate in discovery_candidates(
                provider
            ):
                print(
                    f"[TRY] "
                    f"{provider['name']}: "
                    f"{candidate}"
                )

                winner = probe(
                    candidate,
                    provider
                )

                if winner:
                    print(
                        f"[FOUND] "
                        f"{provider['name']}: "
                        f"{winner}"
                    )
                    break

        if winner:
            resolved.append(winner)

            old = normalize(
                provider.get(
                    "current",
                    ""
                )
            )

            if old != winner:
                print(
                    f"[UPDATE] "
                    f"{provider['name']}: "
                    f"{old or '(vuoto)'} "
                    f"-> {winner}"
                )

                provider["current"] = winner

                candidates = dedupe(
                    [winner]
                    + provider.get(
                        "candidates",
                        []
                    )
                )

                provider["candidates"] = (
                    candidates[:8]
                )

                changed = True

            else:
                print(
                    f"[OK] "
                    f"{provider['name']}: "
                    f"{winner}"
                )

        else:
            old = normalize(
                provider.get(
                    "current",
                    ""
                )
            )

            if old:
                print(
                    f"[OFFLINE] "
                    f"{provider['name']}: "
                    "nessun dominio con lo stesso nome "
                    "è stato verificato; "
                    f"non pubblico {old}"
                )
            else:
                print(
                    f"[OFFLINE] "
                    f"{provider['name']}: "
                    "nessun dominio verificato trovato"
                )

    # Publish only providers verified during this run.
    OUTPUT_FILE.write_text(
        "\n".join(
            dedupe(resolved)
        )
        + (
            "\n"
            if resolved
            else ""
        ),
        encoding="utf-8"
    )

    if changed:
        PROVIDERS_FILE.write_text(
            json.dumps(
                config,
                ensure_ascii=False,
                indent=2
            )
            + "\n",
            encoding="utf-8"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
