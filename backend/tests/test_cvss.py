"""The published CVSS v3.1 examples, checked against our implementation."""

import pytest

from vulncano.cvss import CvssError, parse_vector, roundup, score_all, severity_of

SPEC_EXAMPLES = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.7),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.3),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.0),
    ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.7),
]


@pytest.mark.parametrize("vector,expected", SPEC_EXAMPLES)
def test_base_score_matches_the_spec(vector, expected):
    assert score_all(vector)["base_score"] == expected


def test_roundup_follows_the_specification():
    assert roundup(4.02) == 4.1
    assert roundup(4.00) == 4.0
    assert roundup(0.0) == 0.0
    assert roundup(9.999) == 10.0


def test_temporal_score_applies_the_three_multipliers():
    # CVE-2013-1937, base 6.1, then 6.1 * 0.94 * 0.95 rounded up per the 3.1 rule
    scores = score_all("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", {"E": "P", "RL": "O", "RC": "C"})
    assert scores["base_score"] == 6.1
    assert scores["temporal_score"] == 5.5


def test_environmental_score_uses_the_modified_metrics():
    # CVE-2014-3566 POODLE. A confidentiality requirement of High and a modified C of High lift
    # a 3.1 base to 6.6 once the temporal multipliers are applied.
    scores = score_all(
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        {"E": "F", "RL": "O", "RC": "C", "CR": "H", "IR": "H", "MAC": "H", "MC": "H"},
    )
    assert scores["base_score"] == 3.1
    assert scores["adapted_score"] == 6.6


def test_environmental_matches_the_spec_worked_example():
    # CVE-2019-9042, base 7.2 unchanged when every environmental metric stays not defined
    vector = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    scores = score_all(vector)
    assert scores["base_score"] == 7.2
    assert scores["adapted_score"] == 7.2


def test_environmental_requirements_raise_the_score():
    base = score_all("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    raised = score_all("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", {"CR": "H"})
    assert raised["adapted_score"] > base["base_score"]


def test_severity_bands():
    assert severity_of(9.8) == "Critical"
    assert severity_of(7.0) == "High"
    assert severity_of(6.9) == "Medium"
    assert severity_of(3.9) == "Low"
    assert severity_of(0.0) == "Info"
    assert severity_of(None) == "Info"


def test_vector_round_trip_keeps_the_selections():
    scores = score_all("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", {"E": "P", "CR": "H"})
    assert "E:P" in scores["vector"]
    assert "CR:H" in scores["vector"]
    assert scores["vector"].startswith("CVSS:3.1/AV:N")


def test_bad_vectors_are_rejected_with_a_message():
    with pytest.raises(CvssError, match="missing base metrics"):
        parse_vector("CVSS:3.1/AV:N/AC:L")
    with pytest.raises(CvssError, match="bad value"):
        parse_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    with pytest.raises(CvssError, match="not a CVSS v3 vector"):
        parse_vector("AV:N/AC:L")
