"""vulntriage — triage dependency CVEs by real-world exploitability.

Most scanners dump a wall of CVEs sorted by CVSS severity. The problem a
defender actually has is *what to fix first* — and severity is a weak proxy for
that. vulntriage correlates three signals instead:

    known CVEs        (OSV.dev — which vulns affect your exact versions)
  × actively exploited (CISA KEV — is it being used in attacks right now)
  × exploitation odds  (FIRST EPSS — probability of exploitation in 30 days)

and sorts so the handful you should fix today floats to the top.

    from vulntriage import Package, triage
    report = triage([Package("django", "2.2.0")])
    for f in report.findings:
        print(f.priority_label, f.cve, f.package.name)
"""
from .model import Finding, Package, TriageReport
from .triage import triage
from .cvss import base_score, severity_label

__version__ = "0.1.0"
__all__ = [
    "Package",
    "Finding",
    "TriageReport",
    "triage",
    "base_score",
    "severity_label",
]
