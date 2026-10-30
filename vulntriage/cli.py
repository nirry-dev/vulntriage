"""Command line: `vulntriage scan -r requirements.txt`.

    vulntriage scan -r requirements.txt
    pip freeze | vulntriage scan -r -
    vulntriage scan -p "django==2.2.0" -p "pyyaml==5.3.1" --json

Exit code is 0 when nothing urgent is found, 1 when any P1/P2 finding is present
(handy as a CI gate), and 2 on a usage error.
"""
import argparse
import json
import os
import sys

from . import epss as epss_mod
from . import kev as kev_mod
from . import inputs
from .osv import query_package
from .triage import triage


def _cache_dir():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return os.path.join(base, "vulntriage")


def _collect_packages(args):
    packages, skipped = [], []
    if args.requirement:
        text = sys.stdin.read() if args.requirement == "-" else _read(args.requirement)
        pkgs, skip = inputs.parse_requirements(text, ecosystem=args.ecosystem)
        packages += pkgs
        skipped += skip
    if args.package:
        pkgs, skip = inputs.parse_specs(args.package, ecosystem=args.ecosystem)
        packages += pkgs
        skipped += skip
    return packages, skipped


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def cmd_scan(args):
    packages, skipped = _collect_packages(args)
    if not packages:
        print("no pinned packages to scan (need `name==version` lines)", file=sys.stderr)
        return 2

    kev = {} if args.no_kev else kev_mod.load_kev(
        os.path.join(_cache_dir(), "kev.json"), offline=args.offline
    )
    epss_fn = (lambda cves: {}) if (args.no_epss or args.offline) else epss_mod.fetch_epss

    report = triage(packages, osv_query=query_package, kev=kev, epss_fn=epss_fn)

    if args.json:
        print(_as_json(report, skipped))
    else:
        _print_table(report, skipped, args)

    urgent = any(f.priority <= 2 for f in report.findings)
    return 1 if urgent else 0


def _as_json(report, skipped):
    return json.dumps({
        "scanned": [str(p) for p in report.packages],
        "skipped": skipped,
        "errors": [{"package": str(p), "error": e} for p, e in report.errors],
        "findings": [
            {
                "priority": f.priority_label, "package": f.package.name,
                "version": f.package.version, "cve": f.cve, "in_kev": f.in_kev,
                "kev_due": f.kev_due, "epss": f.epss, "cvss": f.cvss,
                "severity": f.severity, "summary": f.summary,
            }
            for f in report.findings
        ],
    }, indent=2)


def _print_table(report, skipped, args):
    counts = report.by_priority()
    print(f"Scanned {len(report.packages)} packages - "
          f"{len(report.findings)} findings  "
          f"(P1 {counts[1]}  P2 {counts[2]}  P3 {counts[3]}  P4 {counts[4]})")
    if not report.findings:
        print("  no known vulnerabilities for the pinned versions")
    else:
        print()
        print(f"  {'PRI':<4}{'PACKAGE':<22}{'CVE':<18}{'KEV':<5}{'EPSS':>7}  {'CVSS':>5}  SUMMARY")
        for f in report.findings:
            epss = f"{f.epss*100:.1f}%" if f.epss is not None else "-"
            cvss = f"{f.cvss:.1f}" if f.cvss is not None else "-"
            kev = "yes" if f.in_kev else ""
            pkg = f"{f.package.name} {f.package.version}"[:21]
            print(f"  {f.priority_label:<4}{pkg:<22}{f.cve:<18}{kev:<5}{epss:>7}  {cvss:>5}  "
                  f"{f.summary[:48]}")

    for pkg, err in report.errors:
        print(f"  ! {pkg}: {err}", file=sys.stderr)
    if skipped and args.verbose:
        print(f"  (skipped {len(skipped)} unpinned/invalid lines)", file=sys.stderr)


def main(argv=None):
    # Summaries from OSV can carry characters a legacy console can't encode;
    # replace rather than crash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    p = argparse.ArgumentParser(
        prog="vulntriage",
        description="Triage dependency CVEs by real-world exploitability (OSV + CISA KEV + EPSS).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="scan pinned dependencies")
    ps.add_argument("-r", "--requirement", help="requirements file, or '-' for stdin")
    ps.add_argument("-p", "--package", action="append", metavar="NAME==VER",
                    help="a package to scan (repeatable)")
    ps.add_argument("--ecosystem", default="PyPI", help="OSV ecosystem (default: PyPI)")
    ps.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ps.add_argument("--no-epss", action="store_true", help="skip the EPSS lookup")
    ps.add_argument("--no-kev", action="store_true", help="skip the CISA KEV lookup")
    ps.add_argument("--offline", action="store_true",
                    help="use cached KEV only; no KEV/EPSS network calls (OSV still required)")
    ps.add_argument("-v", "--verbose", action="store_true")
    ps.set_defaults(func=cmd_scan)

    args = p.parse_args(argv)
    return args.func(args)
