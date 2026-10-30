"""CISA KEV — the Known Exploited Vulnerabilities catalog.

A single public JSON file listing CVEs that are being exploited in the wild. It's
the strongest "fix this now" signal there is, so we fetch it once, cache it on
disk with a TTL, and hand back a {CVE: due_date} map.
"""
import json
import os
import time
import urllib.error
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _fetch(timeout):
    with urllib.request.urlopen(KEV_URL, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def load_kev(cache_path, ttl=86400, timeout=60, offline=False):
    """Return {cve_id: due_date}. Uses the cache within `ttl`; `offline` never fetches.

    Degrades to an empty map (rather than raising) if the catalog can't be
    fetched and no cache exists — the scan still runs, just without the KEV signal.
    """
    fresh = os.path.exists(cache_path) and (time.time() - os.path.getmtime(cache_path) < ttl)
    raw = None
    if fresh or (offline and os.path.exists(cache_path)):
        with open(cache_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    elif not offline:
        try:
            raw = _fetch(timeout)
            os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write(raw)
        except (urllib.error.URLError, TimeoutError, OSError):
            if os.path.exists(cache_path):  # fall back to a stale cache
                with open(cache_path, "r", encoding="utf-8") as fh:
                    raw = fh.read()

    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return {v["cveID"]: v.get("dueDate") for v in data.get("vulnerabilities", []) if v.get("cveID")}
