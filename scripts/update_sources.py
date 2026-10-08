#!/usr/bin/env python3
# Tairon Sources Auto Update V3 - manual allowlist, no stale providers or pending sources
import html as html_lib
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode

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
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
}

TIMEOUT = 15
SEARCH_TIMEOUT = 18
CT_TIMEOUT = 20
MAX_CT_RESULTS = 200
MAX_DISCOVERY_PROBES = 12
FAILURES_BEFORE_OFFLINE = 3
BLOCKED_DISCOVERY_EVERY = 4
TEST_QUERY = "natale sul nilo"

BLOCK_MARKERS = (
    "just a moment",
    "checking your browser",
    "verify you are human",
    "verifica di essere umano",
    "attention required",
    "cloudflare",
    "captcha",
    "access denied",
    "too many requests",
    "you have been blocked",
    "sorry, you have been blocked",
    "site unavailable",
    "unable to access this site",
)

SEARCH_NAMES = {"story", "s", "search", "q", "keyword", "term"}
RESULT_MARKERS = (
    'id="fullsearch"',
    'id="searchinput"',
    'class="search-page',
    'class="search-results',
    'class="search-result',
    'class="result-item',
    "site search",
    "search results",
    "risultati ricerca",
    "risultati di ricerca",
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


def same_origin_host(a: str, b: str) -> bool:
    return clean_host(hostname(a)) == clean_host(hostname(b))


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


class SearchPageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current_form = None
        self.loose_inputs = []
        self.has_hs_input = False
        self.data_pages = []
        self.title_parts = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = {str(k).lower(): (v or "") for k, v in attrs}
        if tag.lower() == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self.current_form)
            return
        if tag.lower() == "input":
            item = {
                "name": attrs.get("name", ""),
                "type": attrs.get("type", "text").lower(),
                "value": attrs.get("value", ""),
                "placeholder": attrs.get("placeholder", ""),
                "class": attrs.get("class", ""),
                "disabled": "disabled" in attrs,
            }
            if "hs-input" in item["class"].split():
                self.has_hs_input = True
            if self.current_form is not None:
                self.current_form["inputs"].append(item)
            else:
                self.loose_inputs.append(item)
            return
        if "data-page" in attrs:
            self.data_pages.append(attrs.get("data-page", ""))
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self.current_form = None
        elif tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)

    @property
    def title(self):
        return " ".join(self.title_parts).strip()


def parse_search_page(text: str):
    parser = SearchPageParser()
    try:
        parser.feed(text or "")
    except Exception:
        pass
    return parser


def is_search_input(item: dict) -> bool:
    if item.get("disabled") or item.get("type") == "hidden":
        return False
    name = (item.get("name") or "").lower()
    placeholder = (item.get("placeholder") or "").lower()
    return (
        name in SEARCH_NAMES
        or item.get("type") == "search"
        or "cerca" in placeholder
        or "search" in placeholder
    )


def inertia_search_url(page_text: str, landing_url: str):
    # Mirrors SourceSearchScripts: read declared search.uri and replace {locale}.
    match = re.search(r'"search"\s*:\s*\{\s*"uri"\s*:\s*"([^"\n]+)"', page_text or "")
    if not match:
        return None
    try:
        uri = json.loads('"' + match.group(1) + '"')
    except Exception:
        uri = match.group(1).replace("\\/", "/")

    locale = None
    parser = parse_search_page(page_text)
    for raw in parser.data_pages:
        try:
            obj = json.loads(html_lib.unescape(raw))
            candidate = ((obj or {}).get("props") or {}).get("locale")
            if candidate:
                locale = str(candidate)
                break
        except Exception:
            continue
    if locale:
        uri = uri.replace("{locale}", locale)
    if "{" in uri:
        return None
    return urljoin(landing_url + "/", uri.lstrip("/"))


def choose_search_request(page_text: str, landing_url: str, query: str):
    """Return (method, url, params/data, kind) using the same routes Tairon understands."""
    parser = parse_search_page(page_text)

    inertia = inertia_search_url(page_text, landing_url)
    if inertia:
        return "get", inertia, {"q": query}, "inertia"

    if parser.has_hs_input or re.search(r'class=["\'][^"\']*\bhs-input\b', page_text or "", re.I):
        return "get", urljoin(landing_url + "/", "/search"), {"q": query}, "react-search"

    for form in parser.forms:
        candidate = next((i for i in form["inputs"] if is_search_input(i)), None)
        if not candidate:
            continue
        action = (form.get("action") or landing_url).strip()
        if action.lower().startswith("javascript:"):
            continue
        target = urljoin(landing_url + "/", action)
        payload = {}
        for inp in form["inputs"]:
            name = (inp.get("name") or "").strip()
            if not name or inp.get("disabled"):
                continue
            if inp.get("type") in ("submit", "button", "image", "file"):
                continue
            payload[name] = inp.get("value", "")

        search_name = (candidate.get("name") or "").strip()
        if not search_name:
            continue
        payload[search_name] = query
        if search_name == "story":
            if "do" in payload:
                payload["do"] = "search"
            if "subaction" in payload:
                payload["subaction"] = "search"
            if "search_start" in payload:
                payload["search_start"] = "0"
        method = (form.get("method") or "get").lower()
        return ("post" if method == "post" else "get"), target, payload, f"form:{search_name}"

    for item in parser.loose_inputs:
        if not is_search_input(item):
            continue
        name = (item.get("name") or "").lower()
        if name == "s":
            return "get", urljoin(landing_url + "/", "/"), {"s": query}, "wordpress"

    return None


def search_response_compatible(response, landing_url: str, request_kind: str, query: str):
    text = response.text or ""
    if looks_blocked(response.status_code, text):
        return False, "blocked", f"search HTTP {response.status_code} / anti-bot"
    if response.status_code >= 400:
        return False, "incompatible", f"search HTTP {response.status_code}"
    if not same_origin_host(response.url, landing_url):
        return False, "incompatible", "ricerca reindirizzata fuori origine"

    content_type = (response.headers.get("content-type") or "").lower()
    if "json" in content_type or text.lstrip().startswith("{"):
        try:
            obj = response.json()
            props = obj.get("props") if isinstance(obj, dict) else None
            if isinstance(props, dict):
                titles = props.get("titles")
                if isinstance(titles, (list, dict)):
                    return True, "valid", f"ricerca compatibile ({request_kind}, JSON titles)"
            if isinstance(obj, dict) and isinstance(obj.get("data"), list):
                return True, "valid", f"ricerca compatibile ({request_kind}, JSON data)"
        except Exception:
            pass

    low = text[:500000].lower()
    # DLE pages need a recognizable search response, matching SourceSearchScripts.pageStateScript.
    has_dle = bool(re.search(r'<input[^>]+name=["\']story["\']', low, re.I))
    if has_dle:
        if any(marker in low for marker in RESULT_MARKERS) or re.search(r"site search|search results|risultati.*ricerca", low, re.I):
            return True, "valid", f"ricerca compatibile ({request_kind}, DLE results)"
        return False, "incompatible", "DLE raggiunto ma risposta ricerca non riconosciuta"

    # For non-DLE providers Tairon's pageState considers a completed, same-origin page ready.
    # Require evidence that the submitted search actually changed state, to avoid accepting a home page silently.
    parsed = urlparse(response.url)
    query_lower = query.lower()
    evidence = (
        query_lower in low
        or bool(parsed.query)
        or "search" in parsed.path.lower()
        or any(marker in low for marker in RESULT_MARKERS)
        or request_kind in ("inertia", "react-search")
    )
    if evidence:
        return True, "valid", f"ricerca compatibile ({request_kind})"
    return False, "incompatible", "pagina HTTP 200 ma ricerca non confermata"


def app_search_probe(url: str, provider: dict):
    """App-aware validation mirroring Tairon SourceSearchScripts.

    Returns (winner, state, detail), where state is:
    valid | blocked | incompatible | dead | mismatch | unreachable
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
        session = requests.Session()
        session.headers.update(HEADERS)
        try:
            response = session.get(
                candidate_url,
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
            if not html_matches(text, final_host, provider):
                best_state = "mismatch"
                best_detail = "pagina raggiunta ma firma provider non trovata"
                continue

            request_spec = choose_search_request(text, final, TEST_QUERY)
            if not request_spec:
                best_state = "incompatible"
                best_detail = "sito raggiungibile ma Tairon non trova un controllo/route ricerca"
                continue

            method, search_url, payload, kind = request_spec
            try:
                if method == "post":
                    search_response = session.post(
                        search_url,
                        data=payload,
                        timeout=SEARCH_TIMEOUT,
                        allow_redirects=True,
                        headers={"Referer": final},
                    )
                else:
                    search_response = session.get(
                        search_url,
                        params=payload,
                        timeout=SEARCH_TIMEOUT,
                        allow_redirects=True,
                        headers={"Referer": final},
                    )
            except requests.RequestException as exc:
                best_state = "incompatible"
                best_detail = f"ricerca non eseguibile: {exc.__class__.__name__}"
                continue

            ok, state, detail = search_response_compatible(
                search_response,
                final,
                kind,
                TEST_QUERY,
            )
            if ok:
                winner = final
                if winner.startswith("http://"):
                    winner = "https://" + winner[len("http://"):]
                # Preserve configured path when it is meaningful (e.g. /it/movies).
                configured_path = urlparse(url).path.rstrip("/")
                if configured_path and configured_path != "/" and not urlparse(winner).path.rstrip("/"):
                    winner = winner.rstrip("/") + configured_path
                return normalize(winner), "valid", detail

            best_state = state
            best_detail = detail

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
                for cert_name in str(row.get("name_value", "")).splitlines():
                    domain = clean_cert_name(cert_name)
                    if not domain:
                        continue
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
        value -= domain.count(".") * 4
        if current_suffix and domain.endswith("." + current_suffix):
            value += 2
        value -= len(domain) / 100
        return value

    domains.sort(key=score, reverse=True)
    urls = []
    for domain in domains[:MAX_DISCOVERY_PROBES]:
        root = "https://" + domain
        if path:
            urls.append(root + path)
        urls.append(root)
    return dedupe(urls)


def set_meta(provider: dict, key: str, value):
    if provider.get(key) != value:
        provider[key] = value
        return True
    return False


def prune_to_current(provider: dict, current: str, label: str):
    old_candidates = dedupe(provider.get("candidates", []))
    if not current:
        return False
    if old_candidates == [current]:
        return False
    removed = [u for u in old_candidates if u != current]
    provider["candidates"] = [current]
    if removed:
        print(f"[{label}] {provider.get('name', 'provider')}: rimossi candidate obsoleti: " + ", ".join(removed))
    return True




# providers.json is the ONLY authority for the list of providers.
# Removing an entry there permanently removes it from the published list;
# no historic candidates, last-known-good or pending queue is consulted.
def main():
    config = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
    entries = config.get("providers", [])
    if not isinstance(entries, list):
        raise ValueError("providers deve essere una lista")

    published = []
    ids = set()
    changed = False
    for provider in entries:
        if not isinstance(provider, dict):
            raise ValueError("Ogni provider deve essere un oggetto JSON")
        provider_id = str(provider.get("id", "")).strip()
        current = normalize(provider.get("current", ""))
        if not provider_id or not current or not current.startswith(("https://", "http://")):
            raise ValueError("Provider privo di id o current URL valido")
        if provider_id in ids:
            raise ValueError("ID provider duplicato: " + provider_id)
        ids.add(provider_id)
        name = provider.get("name") or provider_id

        # Purge all old state, even for providers still on the allowlist.
        for key in list(provider):
            if key.startswith("pending_") or key.startswith("auto_") or key in (
                "last_known_good", "app_validation", "removed", "archived",
            ):
                del provider[key]
                changed = True
        if provider.get("current") != current:
            provider["current"] = current
            changed = True
        if provider.get("candidates") != [current]:
            provider["candidates"] = [current]
            changed = True

        # Publish manually selected URLs even if GitHub is blocked by anti-bot.
        # This is required to test them on Tairon; GitHub cannot confirm playback.
        published.append(current)
        print(f"[ALLOWLIST] {name}: {current} -> pubblicata per test")
        winner, state, detail = app_search_probe(current, provider)
        print(f"[CHECK-APP] {name}: {current} -> {state} ({detail})")
        if winner:
            winner = normalize(winner)
            # Only update a provider when the validated redirect is recognizably
            # the same source; do not silently adopt a different brand.
            if winner != current and html_matches('', hostname(winner), provider):
                print(f"[REDIRECT] {name}: {current} -> {winner}")
                published[-1] = winner
                provider["current"] = winner
                provider["candidates"] = [winner]
                changed = True
            continue

        # Keep blocked/incompatible/offline sites visible until the USER removes
        # them from providers.json. No pending queue, no silent disappearance.
        if state == "blocked":
            print(f"[KEEP-MANUAL] {name}: GitHub anti-bot; visibile per test Android")
            continue

        # Auto-update is scoped STRICTLY to this provider ID, never the global
        # history. Only a domain with a matching provider name and two successful
        # app-search probes in this run may replace its configured URL.
        print(f"[DISCOVERY] {name}: provo domini alternativi per questo provider")
        for candidate in discovery_candidates(provider):
            candidate = normalize(candidate)
            if candidate == current:
                continue
            # Require provider identity in the host, not just in page text.
            labels = [compact_label(provider.get("base_name", ""))]
            labels += [compact_label(x) for x in provider.get("match_any", [])]
            host_label = compact_label(first_label(hostname(candidate)))
            if not host_label or not any(
                label and (label in host_label or host_label in label)
                for label in labels
            ):
                continue
            first, first_state, _ = app_search_probe(candidate, provider)
            if not first:
                continue
            second, second_state, _ = app_search_probe(candidate, provider)
            if not second or normalize(first) != normalize(second):
                continue
            replacement = normalize(first)
            print(f"[AUTO-UPDATE] {name}: {current} -> {replacement} (due verifiche)")
            published[-1] = replacement
            provider["current"] = replacement
            provider["candidates"] = [replacement]
            changed = True
            break
        else:
            print(f"[KEEP-MANUAL] {name}: {state}; resta pubblicata fino a rimozione manuale")

    # Atomic rewrite: never append to an old list. Removed entries cannot survive.
    contents = "\n".join(dedupe(published)) + ("\n" if published else "")
    OUTPUT_FILE.write_text(contents, encoding="utf-8")
    if changed:
        PROVIDERS_FILE.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[LIVE-REBUILT] {len(dedupe(published))} URL; nessuna sorgente sospesa o archiviata")
    return 0

if __name__ == "__main__":
    sys.exit(main())
