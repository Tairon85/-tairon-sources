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
    out = []
    seen = set()

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
    markers = [
        m.lower().strip()
        for m in provider.get("match_any", [])
        if m and m.strip()
    ]

    hay = (
        host
        + "\n"
        + (text or "")[:300000]
    ).lower()

    return bool(markers) and any(
        marker in hay
        for marker in markers
    )


def probe(url: str, provider: dict):
    url = normalize(url)

    if not url:
        return None

    attempts = [
        url,
        url.replace("https://", "http://", 1)
    ]

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
            host = hostname(final)

            if html_matches(
                response.text or "",
                host,
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


def clean_cert_name(name: str):
    name = (name or "").strip().lower()
    name = name.replace("*.", "")

    if not name:
        return None

    if "/" in name or " " in name:
        return None

    if not re.fullmatch(
        r"[a-z0-9.-]+\.[a-z]{2,63}",
        name
    ):
        return None

    return name


def ct_discover_domains(provider: dict):
    found = []
    seen = set()

    queries = provider.get(
        "ct_queries",
        []
    )

    for query in queries:
        query = (
            query
            or ""
        ).strip().lower()

        if not query:
            continue

        try:
            url = (
                "https://crt.sh/"
                f"?q=%25{query}%25"
                "&output=json"
            )

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=CT_TIMEOUT
            )

            if response.status_code != 200:
                continue

            data = response.json()

            if not isinstance(data, list):
                continue

            for row in data[
                :MAX_CT_RESULTS_PER_QUERY
            ]:
                raw = row.get(
                    "name_value",
                    ""
                )

                for cert_name in str(
                    raw
                ).splitlines():

                    domain = clean_cert_name(
                        cert_name
                    )

                    if not domain:
                        continue

                    compact = domain.replace(
                        "-",
                        ""
                    )

                    valid_token = any(
                        q
                        and q in compact
                        for q in queries
                    )

                    if not valid_token:
                        continue

                    if domain not in seen:
                        seen.add(domain)
                        found.append(domain)

        except (
            requests.RequestException,
            ValueError
        ):
            continue

        time.sleep(0.4)

    return found


def discovery_candidates(provider: dict):
    current = hostname(
        provider.get(
            "current",
            ""
        )
    )

    configured = [
        hostname(x)
        for x in provider.get(
            "candidates",
            []
        )
        if x
    ]

    domains = ct_discover_domains(
        provider
    )

    def score(domain):
        s = 0

        compact = domain.replace(
            "-",
            ""
        )

        for query in provider.get(
            "ct_queries",
            []
        ):
            if query and query in compact:
                s += 20

        if current:
            if (
                domain.split(".")[0]
                == current.split(".")[0]
            ):
                s += 30

        for known in configured:
            if (
                known
                and domain.split(".")[0]
                == known.split(".")[0]
            ):
                s += 20

        s -= domain.count(".") * 2
        s -= len(domain) / 100

        return s

    domains.sort(
        key=score,
        reverse=True
    )

    return [
        "https://" + domain
        for domain in domains[
            :MAX_DISCOVERY_PROBES
        ]
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

        # 1. Prova domini conosciuti
        for candidate in known:
            winner = probe(
                candidate,
                provider
            )

            if winner:
                break

        # 2. Auto-discovery
        if not winner:
            print(
                f"[DISCOVERY] "
                f"{provider['name']}: "
                "cerco nuovi domini..."
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
                    "nessun dominio verificato "
                    f"trovato; non pubblico {old}"
                )

            else:
                print(
                    f"[OFFLINE] "
                    f"{provider['name']}: "
                    "nessun dominio verificato "
                    "trovato"
                )

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
