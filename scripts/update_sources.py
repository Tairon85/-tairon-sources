#!/usr/bin/env python3
# Tairon Sources Auto Update V2.5 - prune automatico dei domini obsoleti
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
    ),
    "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
}

TIMEOUT = 15
CT_TIMEOUT = 20
MAX_CT_RESULTS = 200
MAX_DISCOVERY_PROBES = 80
FAILURES_BEFORE_OFFLINE = 3
MAX_CANDIDATES_SAVED = 10

BLOCK_MARKERS = (
    "just a moment",
    "checking your browser",
    "verify you are human",
    "attention required",
    "cloudflare",
    "captcha",
    "access denied",
    "too many requests",
)


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


def compact_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def current_path(provider: dict) -> str:
    try:
        path = urlparse(provider.get("current", "")).path or ""
        if path == "/":
            return ""
        return path.rstrip("/")
    except Exception:
        return ""


def clean_cert_name(name: str):
    name = (name or "").strip().lower().replace("*.", "")
    if not name or "/" in name or " " in name:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", name):
        return None
    return clean_host(name)


def provider_labels(provider: dict):
    raw = [provider.get("base_name", "")]
    raw.extend(provider.get("match_any", []))
    raw.append(first_label(hostname(provider.get("current", ""))))

    labels = []
    seen = set()
    for value in raw:
        value = (value or "").strip().lower()
        if not value:
            continue

        # Versione domain-safe: spazi -> trattini, caratteri estranei rimossi.
        domainish = re.sub(r"[^a-z0-9-]", "", value.replace(" ", "-"))
        for item in (value, domainish):
            key = compact_label(item)
            if item and key and key not in seen:
                seen.add(key)
                labels.append(item)

    return labels


def html_matches(text: str, host: str, provider: dict) -> bool:
    markers = [
        m.lower().strip()
        for m in provider.get("match_any", [])
        if m and m.strip()
    ]
    haystack = (host + "\n" + (text or "")[:350000]).lower()
    return bool(markers) and any(marker in haystack for marker in markers)


def looks_blocked(status_code: int, text: str) -> bool:
    sample = (text or "")[:120000].lower()
    if status_code in (401, 403, 429, 503):
        return True
    return any(marker in sample for marker in BLOCK_MARKERS)


def probe(url: str, provider: dict):
    """Ritorna (winner, state, detail).

    state: valid | blocked | dead | mismatch | unreachable
    """
    url = normalize(url)
    if not url:
        return None, "dead", "URL vuoto"

    attempts = [url]
    if url.startswith("https://"):
        attempts.append("http://" + url[len("https://"):])

    best_state = "unreachable"
    best_detail = "nessuna risposta"

    for candidate_url in dedupe(attempts):
        try:
            response = requests.get(
                candidate_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True,
            )

            final = normalize(response.url)
            final_host = hostname(final)
            text = response.text or ""

            if looks_blocked(response.status_code, text):
                best_state = "blocked"
                best_detail = f"HTTP {response.status_code} / protezione anti-bot"
                continue

            if response.status_code in (404, 410):
                best_state = "dead"
                best_detail = f"HTTP {response.status_code}"
                continue

            if response.status_code >= 400:
                best_state = "unreachable"
                best_detail = f"HTTP {response.status_code}"
                continue

            if html_matches(text, final_host, provider):
                if final.startswith("http://"):
                    final = "https://" + final[len("http://"):]
                return final, "valid", f"HTTP {response.status_code}"

            best_state = "mismatch"
            best_detail = "pagina raggiunta ma firma provider non trovata"

        except requests.RequestException as exc:
            best_state = "unreachable"
            best_detail = exc.__class__.__name__

    return None, best_state, best_detail


def ct_discover(provider: dict):
    aliases = {compact_label(x) for x in provider_labels(provider) if compact_label(x)}
    if not aliases:
        return []

    found = []
    seen = set()

    for label in provider_labels(provider):
        query_label = re.sub(r"[^a-z0-9-]", "", label.lower())
        if not query_label:
            continue

        url = f"https://crt.sh/?q={query_label}.%25&output=json"

        try:
            response = requests.get(url, headers=HEADERS, timeout=CT_TIMEOUT)
            if response.status_code != 200:
                continue

            data = response.json()
            if not isinstance(data, list):
                continue

            for row in data[:MAX_CT_RESULTS]:
                raw = row.get("name_value", "")
                for cert_name in str(raw).splitlines():
                    domain = clean_cert_name(cert_name)
                    if not domain:
                        continue

                    # Accetta lo stesso nome anche con/ senza trattini.
                    if compact_label(first_label(domain)) not in aliases:
                        continue

                    if domain not in seen:
                        seen.add(domain)
                        found.append(domain)

        except (requests.RequestException, ValueError):
            continue

    return found


def discovery_candidates(provider: dict):
    current_host = clean_host(hostname(provider.get("current", "")))
    current_suffix = current_host.split(".", 1)[1] if "." in current_host else ""
    path = current_path(provider)

    domains = ct_discover(provider)

    def score(domain):
        value = 0
        # Preferisci domini semplici, non sottodomini profondi.
        value -= domain.count(".") * 4
        # Il vecchio suffisso è solo un piccolo indizio, non un requisito.
        if current_suffix and domain.endswith("." + current_suffix):
            value += 2
        value -= len(domain) / 100
        return value

    domains.sort(key=score, reverse=True)

    urls = []
    for domain in domains[:MAX_DISCOVERY_PROBES]:
        root = "https://" + domain
        # Prima prova lo stesso path del provider corrente, poi la home.
        if path:
            urls.append(root + path)
        urls.append(root)

    return dedupe(urls)


def set_meta(provider: dict, key: str, value):
    if provider.get(key) != value:
        provider[key] = value
        return True
    return False


def main():
    config = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
    resolved = []
    changed = False

    for provider in config.get("providers", []):
        name = provider.get("name") or provider.get("id") or "provider"
        known = dedupe(
            [provider.get("current", "")]
            + provider.get("candidates", [])
        )

        winner = None
        probe_states = []

        # 1) Prova dominio attuale e candidati già conosciuti.
        for candidate in known:
            found, state, detail = probe(candidate, provider)
            probe_states.append(state)
            print(f"[CHECK] {name}: {candidate} -> {state} ({detail})")
            if found:
                winner = found
                break

        # 2) Se non funziona, cerca varianti dello stesso brand via CT.
        if not winner:
            print(
                f"[DISCOVERY] {name}: domini noti non validi; "
                "cerco varianti dello stesso nome/brand..."
            )

            for candidate in discovery_candidates(provider):
                found, state, detail = probe(candidate, provider)
                probe_states.append(state)
                print(f"[TRY] {name}: {candidate} -> {state} ({detail})")
                if found:
                    winner = found
                    print(f"[FOUND] {name}: {winner}")
                    break

        if winner:
            resolved.append(winner)
            old = normalize(provider.get("current", ""))
            old_candidates = dedupe(provider.get("candidates", []))

            if old != winner:
                print(f"[UPDATE] {name}: {old or '(vuoto)'} -> {winner}")
                provider["current"] = winner
                changed = True
            else:
                print(f"[OK] {name}: {winner}")

            # V2.5: il provider valido diventa l'unico candidate persistente.
            # I domini precedenti vengono eliminati, così Tairon non può più
            # ripescare URL obsoleti dopo un cambio di dominio.
            clean_candidates = [winner]
            if old_candidates != clean_candidates:
                removed = [u for u in old_candidates if u != winner]
                provider["candidates"] = clean_candidates
                changed = True
                if removed:
                    print(
                        f"[PRUNE] {name}: rimossi candidate obsoleti: "
                        + ", ".join(removed)
                    )

            changed |= set_meta(provider, "auto_status", "ok")
            changed |= set_meta(provider, "auto_failures", 0)
            continue

        current = normalize(provider.get("current", ""))

        # Un blocco anti-bot non significa che il dominio sia morto.
        # In questo caso manteniamo il CURRENT e riproviamo al giro successivo.
        # V2.6: anche se il sito e' bloccato, ripuliamo i candidate obsoleti
        # e lasciamo solo il current, cosi' Tairon non riprova vecchi domini.
        if "blocked" in probe_states:
            if current:
                resolved.append(current)

                old_candidates = dedupe(provider.get("candidates", []))
                if old_candidates != [current]:
                    removed = [url for url in old_candidates if url != current]
                    provider["candidates"] = [current]
                    changed = True
                    if removed:
                        print(
                            f"[PRUNE-BLOCKED] {name}: rimossi candidate obsoleti: "
                            + ", ".join(removed)
                        )

            print(
                f"[BLOCKED] {name}: verifica impedita da anti-bot/rate-limit; "
                "mantengo solo il dominio current e non lo considero morto."
            )
            changed |= set_meta(provider, "auto_status", "blocked")
            continue

        previous_failures = int(provider.get("auto_failures", 0) or 0)
        failures = min(previous_failures + 1, FAILURES_BEFORE_OFFLINE)
        changed |= set_meta(provider, "auto_failures", failures)

        if current and failures < FAILURES_BEFORE_OFFLINE:
            resolved.append(current)
            print(
                f"[KEEP] {name}: verifica fallita {failures}/"
                f"{FAILURES_BEFORE_OFFLINE}; mantengo temporaneamente {current}"
            )
            changed |= set_meta(provider, "auto_status", "warning")
        else:
            print(
                f"[OFFLINE] {name}: {FAILURES_BEFORE_OFFLINE} controlli consecutivi "
                "falliti; escluso dal file live finché non viene ritrovato."
            )
            changed |= set_meta(provider, "auto_status", "offline")

    OUTPUT_FILE.write_text(
        "\n".join(dedupe(resolved)) + ("\n" if resolved else ""),
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
