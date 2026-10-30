"""Data model: a package, a finding, and the overall report.

The ranking lives here because it's the heart of the tool. A finding's
*priority* is a four-tier triage bucket, and its *sort key* orders findings
within and across buckets so the most urgent work is always first.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

_PRIORITY_LABELS = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}


@dataclass(frozen=True)
class Package:
    """A pinned dependency to check."""
    name: str
    version: str
    ecosystem: str = "PyPI"

    def __str__(self):
        return f"{self.name}=={self.version}"


@dataclass
class Finding:
    """One vulnerability affecting one package, enriched with exploit signals."""
    package: Package
    cve: str                      # CVE id, or the OSV id if there's no CVE alias
    summary: str = ""
    cvss: Optional[float] = None  # CVSS v3 base score, if the record carried a vector
    severity: str = ""            # label derived from cvss (Critical/High/...)
    in_kev: bool = False          # listed in CISA's Known Exploited Vulnerabilities
    kev_due: Optional[str] = None # CISA remediation due date, if in KEV
    epss: Optional[float] = None  # FIRST EPSS probability (0..1)
    aliases: List[str] = field(default_factory=list)

    @property
    def priority(self) -> int:
        """Triage bucket, 1 (most urgent) .. 4 (least). Exploitability first.

        P1 — actively exploited in the wild (in CISA KEV). Fix now.
        P2 — high odds or critical: EPSS >= 10%, or CVSS >= 9.
        P3 — meaningful: EPSS >= 1%, or CVSS >= 7.
        P4 — everything else.
        """
        if self.in_kev:
            return 1
        epss = self.epss or 0.0
        cvss = self.cvss or 0.0
        if epss >= 0.10 or cvss >= 9.0:
            return 2
        if epss >= 0.01 or cvss >= 7.0:
            return 3
        return 4

    @property
    def priority_label(self) -> str:
        return _PRIORITY_LABELS[self.priority]

    def sort_key(self) -> Tuple:
        # Bucket first, then the strongest real-world signals, then a stable tie-break.
        return (self.priority, -(self.epss or 0.0), -(self.cvss or 0.0),
                self.package.name, self.cve)


@dataclass
class TriageReport:
    findings: List[Finding]
    errors: List[Tuple[Package, str]] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)

    def by_priority(self):
        """Count of findings in each bucket, e.g. {1: 2, 2: 0, 3: 5, 4: 1}."""
        counts = {1: 0, 2: 0, 3: 0, 4: 0}
        for f in self.findings:
            counts[f.priority] += 1
        return counts
