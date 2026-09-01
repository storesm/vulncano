"""CVSS v3.1 base, temporal and environmental scoring, implemented from the specification."""

import math

BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
TEMPORAL_METRICS = ("E", "RL", "RC")
ENVIRONMENTAL_METRICS = ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

EXPLOIT_CODE_MATURITY = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
REMEDIATION_LEVEL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
REPORT_CONFIDENCE = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
REQUIREMENT = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}

SEVERITY_BANDS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))

VALID_VALUES = {
    "AV": set(AV), "AC": set(AC), "PR": {"N", "L", "H"}, "UI": set(UI),
    "S": {"U", "C"}, "C": set(CIA), "I": set(CIA), "A": set(CIA),
    "E": set(EXPLOIT_CODE_MATURITY), "RL": set(REMEDIATION_LEVEL), "RC": set(REPORT_CONFIDENCE),
    "CR": set(REQUIREMENT), "IR": set(REQUIREMENT), "AR": set(REQUIREMENT),
    "MAV": set(AV) | {"X"}, "MAC": set(AC) | {"X"}, "MPR": {"N", "L", "H", "X"},
    "MUI": set(UI) | {"X"}, "MS": {"U", "C", "X"}, "MC": set(CIA) | {"X"},
    "MI": set(CIA) | {"X"}, "MA": set(CIA) | {"X"},
}


class CvssError(ValueError):
    pass


def roundup(value: float) -> float:
    """Round half up to one decimal the way the 3.1 spec defines it, free of float drift."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    if not vector:
        raise CvssError("empty CVSS vector")
    parts = vector.strip().split("/")
    if parts[0] != "CVSS:3.1" and parts[0] != "CVSS:3.0":
        raise CvssError(f"not a CVSS v3 vector: {vector}")
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CvssError(f"malformed metric {part} in {vector}")
        name, value = part.split(":", 1)
        if name not in VALID_VALUES:
            raise CvssError(f"unknown metric {name} in {vector}")
        if value not in VALID_VALUES[name]:
            raise CvssError(f"bad value {value} for metric {name}")
        metrics[name] = value
    missing = [name for name in BASE_METRICS if name not in metrics]
    if missing:
        raise CvssError(f"vector is missing base metrics {', '.join(missing)}")
    return metrics


def build_vector(metrics: dict) -> str:
    order = list(BASE_METRICS) + list(TEMPORAL_METRICS) + list(ENVIRONMENTAL_METRICS)
    parts = [f"{name}:{metrics[name]}" for name in order if metrics.get(name) and metrics[name] != "X"]
    return "/".join(["CVSS:3.1"] + parts)


def severity_of(score: float | None) -> str:
    if score is None:
        return "Info"
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Info"


def _impact_subscore(scope_changed: bool, conf: float, integ: float, avail: float) -> float:
    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if not scope_changed:
        return 6.42 * iss
    return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15


def _exploitability(scope_changed: bool, av: float, ac: float, pr: float, ui: float) -> float:
    return 8.22 * av * ac * pr * ui


def base_score(metrics: dict) -> float:
    scope_changed = metrics["S"] == "C"
    impact = _impact_subscore(scope_changed, CIA[metrics["C"]], CIA[metrics["I"]], CIA[metrics["A"]])
    if impact <= 0:
        return 0.0
    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    exploitability = _exploitability(
        scope_changed, AV[metrics["AV"]], AC[metrics["AC"]], pr_table[metrics["PR"]], UI[metrics["UI"]]
    )
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def temporal_score(metrics: dict) -> float:
    base = base_score(metrics)
    return roundup(
        base
        * EXPLOIT_CODE_MATURITY[metrics.get("E", "X")]
        * REMEDIATION_LEVEL[metrics.get("RL", "X")]
        * REPORT_CONFIDENCE[metrics.get("RC", "X")]
    )


def environmental_score(metrics: dict) -> float:
    modified = {}
    for name in BASE_METRICS:
        override = metrics.get("M" + name, "X")
        modified[name] = metrics[name] if override == "X" else override

    scope_changed = modified["S"] == "C"
    conf_req = REQUIREMENT[metrics.get("CR", "X")]
    integ_req = REQUIREMENT[metrics.get("IR", "X")]
    avail_req = REQUIREMENT[metrics.get("AR", "X")]

    miss = min(
        1 - (1 - CIA[modified["C"]] * conf_req)
        * (1 - CIA[modified["I"]] * integ_req)
        * (1 - CIA[modified["A"]] * avail_req),
        0.915,
    )
    if scope_changed:
        modified_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        modified_impact = 6.42 * miss

    if modified_impact <= 0:
        return 0.0

    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    modified_exploitability = _exploitability(
        scope_changed,
        AV[modified["AV"]],
        AC[modified["AC"]],
        pr_table[modified["PR"]],
        UI[modified["UI"]],
    )
    factor = 1.08 if scope_changed else 1.0
    combined = roundup(min(factor * (modified_impact + modified_exploitability), 10))
    return roundup(
        combined
        * EXPLOIT_CODE_MATURITY[metrics.get("E", "X")]
        * REMEDIATION_LEVEL[metrics.get("RL", "X")]
        * REPORT_CONFIDENCE[metrics.get("RC", "X")]
    )


def score_all(vector: str, extra: dict | None = None) -> dict:
    """Score a base vector, optionally merged with temporal and environmental selections."""
    metrics = parse_vector(vector)
    metrics.update({name: value for name, value in (extra or {}).items() if value and value != "X"})
    base = base_score(metrics)
    adapted = environmental_score(metrics)
    return {
        "base_score": base,
        "base_severity": severity_of(base),
        "temporal_score": temporal_score(metrics),
        "adapted_score": adapted,
        "adapted_severity": severity_of(adapted),
        "vector": build_vector(metrics),
        "metrics": metrics,
    }
