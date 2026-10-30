"""FIRST EPSS — exploitation probability per CVE.

EPSS gives each CVE a probability (0..1) that it will be exploited in the next 30
days. We fetch scores only for the CVEs a scan actually turned up, batched into
the api.first.org query, so there's no multi-megabyte dataset download.
"""
import json
import urllib.error
import urllib.request

API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss(cves, timeout=30, batch=100):
    """Return {cve_id: probability} for the given CVE ids (non-CVE ids are skipped)."""
    ids = [c for c in dict.fromkeys(cves) if c.startswith("CVE-")]
    scores = {}
    for start in range(0, len(ids), batch):
        chunk = ids[start:start + batch]
        url = f"{API_URL}?cve={','.join(chunk)}&limit={len(chunk)}"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError):
            continue  # EPSS is an enrichment; a failure just means no scores this run
        for row in data.get("data", []):
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError, TypeError):
                pass
    return scores
