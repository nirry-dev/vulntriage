"""OSV.dev client — find vulnerabilities affecting a package at a version.

OSV aggregates advisories from many sources (including the NVD, GitHub, and the
language ecosystems) and answers "is version X of package Y affected?" directly,
so we don't have to do CPE matching by hand. One POST per package to
https://api.osv.dev/v1/query; stdlib only.
"""
import json
import urllib.error
import urllib.request

QUERY_URL = "https://api.osv.dev/v1/query"


class OSVError(RuntimeError):
    pass


def query_package(name, version, ecosystem="PyPI", timeout=30):
    """Return OSV's raw list of vulnerability records for name@version."""
    body = json.dumps({
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }).encode("utf-8")
    req = urllib.request.Request(
        QUERY_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("vulns", []) or []
    except urllib.error.HTTPError as exc:
        raise OSVError(f"OSV HTTP {exc.code} for {name}@{version}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise OSVError(f"OSV query failed for {name}@{version}: {exc}") from None


def extract(vuln):
    """Pull (cve_or_id, cvss_vector, summary, aliases) out of one OSV record.

    Prefers a CVE alias as the identifier (so KEV/EPSS can match it); falls back
    to the OSV id (e.g. a GHSA) when there's no CVE.
    """
    aliases = vuln.get("aliases") or []
    osv_id = vuln.get("id", "")
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    if not cve and osv_id.startswith("CVE-"):
        cve = osv_id
    identifier = cve or osv_id

    vector = None
    for sev in vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS_V3") and sev.get("score"):
            vector = sev["score"]
            break

    summary = vuln.get("summary") or (vuln.get("details") or "").strip().split("\n")[0]
    return identifier, vector, summary[:200], list(aliases)
