"""Turn requirements files / `pip freeze` output into `Package`s.

Accepts pinned lines like `django==2.2.0` (the shape `pip freeze` emits), with
comments, blank lines, extras, and environment markers tolerated and skipped.
Only exact `==` pins are usable — a range doesn't name one version to check.
"""
import re

from .model import Package

# name (PEP 503-ish) == version, ignoring extras "[...]" and markers "; ..."
_PIN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)"
)


def parse_requirements(text, ecosystem="PyPI"):
    """Parse requirements/pip-freeze text into (packages, skipped_lines)."""
    packages, skipped = [], []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue  # blank, comment, or an option line like `-r other.txt`
        m = _PIN.match(stripped)
        if m:
            packages.append(Package(name=m.group(1), version=m.group(2), ecosystem=ecosystem))
        else:
            skipped.append(stripped)
    return packages, skipped


def parse_specs(specs, ecosystem="PyPI"):
    """Parse explicit `name==version` strings (e.g. from `--package`)."""
    packages, skipped = [], []
    for spec in specs:
        m = _PIN.match(spec.strip())
        if m:
            packages.append(Package(name=m.group(1), version=m.group(2), ecosystem=ecosystem))
        else:
            skipped.append(spec)
    return packages, skipped
