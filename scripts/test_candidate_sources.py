#!/usr/bin/env python3
"""Run Tairon app-aware checks on candidate URLs WITHOUT changing live files.

Requires the existing scripts/update_sources.py (V2.9 STRICT) in the repo.
"""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "scripts" / "update_sources.py"
CANDIDATES = ROOT / "candidate_sources.json"
RESULTS = ROOT / "candidate_test_results.json"


def main():
    if not UPDATER.exists():
        print(f"Missing {UPDATER}. Keep your existing updater in place.", file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location("tairon_updater", UPDATER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "app_search_probe", None)):
        print("The updater does not expose app_search_probe()", file=sys.stderr)
        return 2

    data = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    results = []
    for candidate in data.get("candidates", []):
        name = candidate["name"]
        url = candidate["current"]
        try:
            winner, state, detail = module.app_search_probe(url, candidate)
        except Exception as exc:
            winner, state, detail = None, "error", f"{type(exc).__name__}: {exc}"
        row = {"name": name, "url": url, "state": state,
               "detail": detail, "validated_url": winner}
        results.append(row)
        print(f"[CANDIDATE] {name}: {url} -> {state} ({detail})")
        if state == "valid":
            print("  [NOTE] Search compatible from GitHub; playback in Tairon NOT verified.")
        elif state == "blocked":
            print("  [NOTE] GitHub anti-bot block; not proof the app cannot access it.")

    RESULTS.write_text(json.dumps({"results": results}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[DONE] {len(results)} candidates tested; no live files modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
