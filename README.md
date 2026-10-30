# vulntriage

**Triage dependency CVEs by real-world exploitability — not just CVSS.**

Most dependency scanners hand you a wall of CVEs sorted by severity. But the
question you actually have is *what do I fix first*, and severity is a weak
answer: plenty of "critical" CVEs are never exploited, while some "medium" ones
are being used in attacks today. `vulntriage` correlates three signals and ranks
accordingly:

```
 known CVEs           OSV.dev   — which vulns affect your exact pinned versions
 × actively exploited CISA KEV  — is it being exploited in the wild right now
 × exploitation odds  FIRST EPSS — probability of exploitation in the next 30 days
```

Pure Python standard library — no SDKs, no local vulnerability database to sync.

```bash
pip freeze | vulntriage scan -r -
```
```
Scanned 42 packages — 6 findings  (P1 1  P2 2  P3 2  P4 1)

  PRI PACKAGE               CVE                KEV      EPSS   CVSS  SUMMARY
  P1  django 2.2.0          CVE-2021-35042     yes     94.2%    9.8  SQL injection via QuerySet.order_by
  P2  pyyaml 5.3.1          CVE-2020-14343     -       22.1%    9.8  Arbitrary code execution in full_load
  P2  jinja2 2.10           CVE-2019-10906     -        3.0%    9.8  Sandbox escape
  ...
```

## Why exploitability, not severity

Three findings can all be "CVSS 9.8 Critical" and have wildly different urgency:

- one is in **CISA KEV** — confirmed exploited in the wild, so it's a *right now* problem;
- one has an **EPSS of 0.4** — a 40% modeled chance of exploitation in 30 days;
- one has an **EPSS of 0.0003** — critical on paper, but nobody's weaponized it.

Fixing them in CVSS order wastes your first move on the least likely one.
`vulntriage` buckets findings by the signal that actually predicts attacks:

| Bucket | Meaning |
| --- | --- |
| **P1** | In CISA KEV — actively exploited. Fix now. |
| **P2** | High odds or critical: EPSS ≥ 10%, or CVSS ≥ 9. |
| **P3** | Meaningful: EPSS ≥ 1%, or CVSS ≥ 7. |
| **P4** | Everything else. |

Within a bucket it sorts by EPSS, then CVSS — so the top of the list is always
the next thing worth your time.

## Data sources

- **[OSV.dev](https://osv.dev)** — one query per package answers "is *this version*
  affected?", so there's no CPE matching to get wrong. OSV aggregates the NVD,
  GitHub advisories, and the language ecosystems.
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** —
  the catalog of vulnerabilities known to be exploited. Fetched once and cached.
- **[FIRST EPSS](https://www.first.org/epss/)** — looked up only for the CVEs a
  scan actually finds, so there's no bulk dataset download.

Everything is a read-only GET/POST to a public endpoint; no API keys.

## Install

```bash
pip install vulntriage        # once published
# or, from a checkout:
pip install -e .
```

No dependencies.

## Use

```bash
# A requirements file, or pip freeze over stdin:
vulntriage scan -r requirements.txt
pip freeze | vulntriage scan -r -

# One-off packages, and machine-readable output:
vulntriage scan -p "django==2.2.0" -p "pyyaml==5.3.1" --json

# Other ecosystems OSV supports (npm, Go, crates.io, Maven, ...):
vulntriage scan -r package-lock.deps.txt --ecosystem npm
```

**As a CI gate** — the exit code is `1` when any **P1/P2** finding is present,
`0` otherwise:

```bash
pip freeze | vulntriage scan -r - || echo "urgent vulnerabilities — failing the build"
```

From Python:

```python
from vulntriage import Package, triage
report = triage([Package("django", "2.2.0")])
for f in report.findings:
    print(f.priority_label, f.cve, f.epss, f.summary)
```

## Design notes & limitations

- **Exact pins only.** It checks `name==version`; a range (`>=2.0`) doesn't name a
  single version to test, so those lines are skipped (and listed with `-v`).
- **EPSS/KEV are advisory signals, not verdicts.** EPSS is a *model*; KEV is
  authoritative about "exploited" but says nothing about your exposure. The tool
  prioritizes — it doesn't decide that something is safe to ignore.
- **Only as current as its sources.** OSV and EPSS are queried live; KEV is cached
  for a day (`--offline` uses the cache only). A brand-new CVE may not be scored
  by EPSS yet.
- **No reachability analysis.** Like every SCA tool at this layer, it flags that a
  vulnerable version is *present*, not that the vulnerable code path is *reached*.

## Learning notes

*What I set out to learn, and what changed how I think about this.*

- **The ranking signal is the product, the data plumbing is commodity.** Fetching
  OSV/KEV/EPSS is easy; the thing with actual value is the decision to sort by
  *exploitability* and the little P1–P4 rubric that encodes it. I spent most of my
  design time on the four lines in `Finding.priority`, not the HTTP.
- **"Critical" is a popularity-independent label, and that's the trap.** Seeing a
  medium-CVSS CVE jump to the top of the list because it's in KEV — ahead of a
  pile of 9.8s nobody exploits — was the moment the whole premise clicked for me.
- **Let the hard part be a known spec, then test it against known answers.** The
  CVSS v3.1 base-score formula is fiddly (scope changes the equations, and it has
  its own round-*up* rule). Implementing it straight from the spec and pinning the
  tests to published scores (9.8, 7.5, 7.8) made it a solved problem instead of a
  guess.
- **Enrich only what you found.** My first cut downloaded the whole EPSS dataset.
  Querying EPSS for just the CVEs a scan surfaces cut a multi-megabyte download to
  a single small request — a reminder to pull on demand, not in bulk.
- **Make failure partial, not fatal.** A dependency scanner that dies because one
  package errored or EPSS was briefly down is useless in CI. Every enrichment
  degrades to "no signal" and per-package errors are collected, not raised, so you
  always get a report.

## Tests

```bash
python -m unittest discover -s tests -v
```

Runs fully offline: the CVSS math is checked against published scores, parsing
against tricky requirement lines, and the correlation/ranking core against fake
OSV/KEV/EPSS data (including that KEV outranks a higher CVSS, and EPSS lifts a
low-severity CVE).

## License

MIT © Nirry
