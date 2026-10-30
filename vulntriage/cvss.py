"""CVSS v3.1 base score, computed from a vector string.

OSV records carry a CVSS *vector* (e.g. "CVSS:3.1/AV:N/AC:L/.../A:H") but not
always a number, so we compute the base score ourselves. This is a direct
implementation of the CVSS v3.1 specification's base-score equations — handy for
display and as a secondary sort signal (the primary one is exploitability).
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _parse(vector):
    parts = {}
    for token in vector.split("/"):
        if ":" in token:
            key, value = token.split(":", 1)
            parts[key] = value
    return parts


def _roundup(value):
    # CVSS's own rounding: up to the nearest 0.1 (not ordinary rounding).
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector):
    """Return the CVSS v3.x base score for a vector string, or None if unparseable."""
    if not vector:
        return None
    try:
        p = _parse(vector)
        changed = p.get("S") == "C"
        av, ac, ui = _AV[p["AV"]], _AC[p["AC"]], _UI[p["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[p["PR"]]
        conf, integ, avail = _CIA[p["C"]], _CIA[p["I"]], _CIA[p["A"]]
    except (KeyError, AttributeError):
        return None

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(raw, 10))


def severity_label(score):
    """Qualitative CVSS v3.1 severity rating for a base score."""
    if score is None:
        return ""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
