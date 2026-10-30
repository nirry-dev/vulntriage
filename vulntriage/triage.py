"""The correlation core: packages in, ranked findings out.

Pure orchestration — every external lookup is an injected callable, so the whole
pipeline runs offline under test with fakes standing in for OSV, KEV, and EPSS.
"""
from concurrent.futures import ThreadPoolExecutor

from . import cvss, osv
from .model import Finding, TriageReport


def triage(packages, osv_query=None, kev=None, epss_fn=None, max_workers=16):
    """Correlate `packages` against OSV, then enrich and rank with KEV + EPSS.

    osv_query(name, version, ecosystem) -> list of OSV records
    kev: {cve: due_date}         (default: empty — no KEV signal)
    epss_fn(cves) -> {cve: prob} (default: none — no EPSS signal)
    """
    packages = list(packages)
    osv_query = osv_query or osv.query_package
    kev = kev if kev is not None else {}
    epss_fn = epss_fn or (lambda cves: {})

    # Stage 1 — query OSV for each package, in parallel.
    def scan(pkg):
        try:
            return pkg, osv_query(pkg.name, pkg.version, pkg.ecosystem), None
        except Exception as exc:  # noqa: BLE001 - surface any client error per package
            return pkg, [], str(exc)

    errors = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(packages) or 1))) as pool:
        results = list(pool.map(scan, packages))

    # OSV often returns several records for one CVE (e.g. a GHSA plus the NVD
    # entry, both aliasing it), so collapse by (package, CVE): keep the highest
    # CVSS, the fullest summary, and the union of aliases.
    merged = {}
    for pkg, vulns, err in results:
        if err:
            errors.append((pkg, err))
        for record in vulns:
            cve, vector, summary, aliases = osv.extract(record)
            score = cvss.base_score(vector)
            key = (pkg, cve)
            existing = merged.get(key)
            if existing is None:
                merged[key] = Finding(
                    package=pkg, cve=cve, summary=summary,
                    cvss=score, severity=cvss.severity_label(score), aliases=list(aliases),
                )
                continue
            if score is not None and (existing.cvss is None or score > existing.cvss):
                existing.cvss = score
                existing.severity = cvss.severity_label(score)
            if len(summary) > len(existing.summary):
                existing.summary = summary
            for alias in aliases:
                if alias not in existing.aliases:
                    existing.aliases.append(alias)

    findings = list(merged.values())

    # Stage 2 — enrich with exploitability signals, then rank.
    cves = [f.cve for f in findings if f.cve.startswith("CVE-")]
    epss = epss_fn(cves) if cves else {}
    for f in findings:
        if f.cve in kev:
            f.in_kev = True
            f.kev_due = kev[f.cve]
        f.epss = epss.get(f.cve)

    findings.sort(key=lambda f: f.sort_key())
    return TriageReport(findings=findings, errors=errors, packages=packages)
