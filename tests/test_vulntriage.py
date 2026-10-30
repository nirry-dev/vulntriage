"""Tests: CVSS math, input parsing, and the correlation/ranking core.

The core is driven with fake OSV/KEV/EPSS data, so everything runs offline.
"""
import unittest

from vulntriage import Package, base_score, severity_label, triage
from vulntriage.inputs import parse_requirements
from vulntriage.osv import extract


class CvssTest(unittest.TestCase):
    def test_known_vectors(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            self.assertEqual(base_score(vector), expected, vector)

    def test_scope_changed_vector(self):
        # A scope change raises the score above the otherwise-identical S:U vector.
        changed = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N")
        unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
        self.assertEqual(changed, 7.2)
        self.assertEqual(unchanged, 6.5)
        self.assertGreater(changed, unchanged)

    def test_labels_and_bad_input(self):
        self.assertEqual(severity_label(9.8), "Critical")
        self.assertEqual(severity_label(7.5), "High")
        self.assertEqual(severity_label(0.0), "None")
        self.assertIsNone(base_score("not-a-vector"))
        self.assertIsNone(base_score(None))


class InputTest(unittest.TestCase):
    def test_parse_requirements(self):
        text = (
            "# comment\n"
            "django==2.2.0\n"
            "PyYAML==5.3.1  # inline\n"
            "requests[security]==2.19.1 ; python_version < '3.8'\n"
            "-r other.txt\n"
            "flask>=2.0\n"          # range: skipped, not an exact pin
            "\n"
        )
        pkgs, skipped = parse_requirements(text)
        self.assertEqual([str(p) for p in pkgs],
                         ["django==2.2.0", "PyYAML==5.3.1", "requests==2.19.1"])
        self.assertIn("flask>=2.0", skipped)


class ExtractTest(unittest.TestCase):
    def test_prefers_cve_alias(self):
        rec = {
            "id": "GHSA-xxxx", "aliases": ["GHSA-xxxx", "CVE-2020-1234"],
            "summary": "bad things",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        cve, vector, summary, aliases = extract(rec)
        self.assertEqual(cve, "CVE-2020-1234")
        self.assertTrue(vector.startswith("CVSS:3.1"))
        self.assertEqual(summary, "bad things")

    def test_falls_back_to_osv_id(self):
        cve, vector, _, _ = extract({"id": "GHSA-yyyy", "aliases": ["GHSA-yyyy"]})
        self.assertEqual(cve, "GHSA-yyyy")
        self.assertIsNone(vector)


# ---- fake data for the correlation core ----

_V_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
_V_MED = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"    # ~2.5

_FAKE_OSV = {
    "django": [
        {"id": "CVE-1111", "aliases": ["CVE-1111"], "summary": "exploited bug",
         "severity": [{"type": "CVSS_V3", "score": _V_CRIT}]},
        {"id": "CVE-2222", "aliases": ["CVE-2222"], "summary": "likely bug",
         "severity": [{"type": "CVSS_V3", "score": _V_MED}]},
    ],
    "pyyaml": [
        {"id": "CVE-3333", "aliases": ["CVE-3333"], "summary": "quiet bug",
         "severity": [{"type": "CVSS_V3", "score": _V_MED}]},
    ],
    "clean": [],
}


def fake_osv(name, version, ecosystem):
    return _FAKE_OSV.get(name, [])


class TriageTest(unittest.TestCase):
    def run_triage(self, packages, kev=None, epss=None):
        return triage(
            packages, osv_query=fake_osv,
            kev=kev or {}, epss_fn=lambda cves: epss or {},
        )

    def test_kev_outranks_everything(self):
        pkgs = [Package("django", "2.2.0"), Package("pyyaml", "5.3.1")]
        # CVE-3333 is only medium CVSS but is in KEV → must rank first (P1).
        report = self.run_triage(pkgs, kev={"CVE-3333": "2024-01-01"})
        self.assertEqual(report.findings[0].cve, "CVE-3333")
        self.assertEqual(report.findings[0].priority_label, "P1")
        self.assertTrue(report.findings[0].in_kev)

    def test_epss_lifts_a_low_severity_cve(self):
        pkgs = [Package("pyyaml", "5.3.1")]        # CVE-3333, medium CVSS alone → P4
        base = self.run_triage(pkgs)
        self.assertEqual(base.findings[0].priority_label, "P4")
        lifted = self.run_triage(pkgs, epss={"CVE-3333": 0.42})  # 42% → P2
        self.assertEqual(lifted.findings[0].priority_label, "P2")

    def test_ranking_and_no_findings(self):
        report = self.run_triage([Package("django", "2.2.0"), Package("clean", "1.0")])
        # Critical (9.8 → P2) sorts above the medium one (P4).
        self.assertEqual([f.cve for f in report.findings], ["CVE-1111", "CVE-2222"])
        self.assertEqual(report.by_priority()[2], 1)

    def test_duplicate_cve_records_are_merged(self):
        # OSV returns the same CVE twice: once with a vector, once without.
        def dup_osv(name, version, ecosystem):
            return [
                {"id": "GHSA-aaaa", "aliases": ["GHSA-aaaa", "CVE-9999"], "summary": "short",
                 "severity": [{"type": "CVSS_V3", "score": _V_CRIT}]},
                {"id": "CVE-9999", "aliases": ["CVE-9999"],
                 "summary": "a much longer and more descriptive summary"},
            ]

        report = triage([Package("x", "1.0")], osv_query=dup_osv,
                        epss_fn=lambda cves: {})
        self.assertEqual(len(report.findings), 1)
        f = report.findings[0]
        self.assertEqual(f.cve, "CVE-9999")
        self.assertEqual(f.cvss, 9.8)                     # kept from the record that had it
        self.assertEqual(f.summary, "a much longer and more descriptive summary")
        self.assertIn("GHSA-aaaa", f.aliases)             # aliases unioned

    def test_errors_are_captured_not_raised(self):
        def boom(name, version, ecosystem):
            raise RuntimeError("network down")

        report = triage([Package("x", "1.0")], osv_query=boom)
        self.assertEqual(report.findings, [])
        self.assertEqual(len(report.errors), 1)
        self.assertIn("network down", report.errors[0][1])


if __name__ == "__main__":
    unittest.main()
