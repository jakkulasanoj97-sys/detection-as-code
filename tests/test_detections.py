"""
test_detections.py - the CI gate for detection content.

Three classes of test, all run on every pull request:
  1. Structure    - every shipped Sigma rule is valid YAML with the required fields
                    and a MITRE ATT&CK technique tag.
  2. True positive - each rule fires on its malicious fixture.
  3. True negative - each rule stays quiet on its benign fixture (no false positives).

A rule that fails any of these blocks the merge. See sigma/_broken_example.yml and
test_broken_rule_is_rejected for the demonstration that the gate actually works.
"""
import sys
from pathlib import Path
import yaml
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from sigma_eval import load_rule, rule_matches_event, evaluate_file  # noqa: E402

SIGMA_DIR = ROOT / "sigma"
FIX = ROOT / "tests" / "fixtures"

# shipped rules exclude any file starting with '_' (e.g. the broken demo)
SHIPPED_RULES = sorted(p for p in SIGMA_DIR.glob("*.yml") if not p.name.startswith("_"))

# rule filename stem -> fixture stem
FIXTURE_MAP = {
    "kerberoasting_4769": "kerberoasting",
    "dcsync_4662": "dcsync",
    "lsass_access_sysmon10": "lsass",
}

REQUIRED_FIELDS = ["title", "id", "description", "logsource", "detection"]


@pytest.mark.parametrize("rule_path", SHIPPED_RULES, ids=lambda p: p.name)
def test_rule_structure(rule_path):
    rule = load_rule(rule_path)
    for field in REQUIRED_FIELDS:
        assert field in rule, f"{rule_path.name} missing required field '{field}'"
    assert "condition" in rule["detection"], f"{rule_path.name} missing detection.condition"


@pytest.mark.parametrize("rule_path", SHIPPED_RULES, ids=lambda p: p.name)
def test_rule_has_attack_tag(rule_path):
    rule = load_rule(rule_path)
    tags = rule.get("tags", [])
    assert any(str(t).startswith("attack.t") for t in tags), \
        f"{rule_path.name} has no MITRE ATT&CK technique tag"


@pytest.mark.parametrize("rule_path", SHIPPED_RULES, ids=lambda p: p.name)
def test_true_positive(rule_path):
    stem = rule_path.stem
    fixture_stem = FIXTURE_MAP.get(stem)
    if not fixture_stem:
        pytest.skip(f"no fixture mapped for {stem}")
    rule = load_rule(rule_path)
    hits = evaluate_file(rule, FIX / "malicious" / f"{fixture_stem}.json")
    assert hits >= 1, f"{rule_path.name} did NOT fire on its malicious fixture"


@pytest.mark.parametrize("rule_path", SHIPPED_RULES, ids=lambda p: p.name)
def test_true_negative(rule_path):
    stem = rule_path.stem
    fixture_stem = FIXTURE_MAP.get(stem)
    if not fixture_stem:
        pytest.skip(f"no fixture mapped for {stem}")
    rule = load_rule(rule_path)
    benign = FIX / "benign" / f"{fixture_stem}.json"
    if not benign.exists():
        pytest.skip("no benign fixture")
    hits = evaluate_file(rule, benign)
    assert hits == 0, f"{rule_path.name} fired on benign data ({hits} false positives)"


def test_broken_rule_is_rejected():
    """The broken demo rule must fail validation - proves the CI gate is real."""
    broken = load_rule(SIGMA_DIR / "_broken_example.yml")
    has_condition = "condition" in broken.get("detection", {})
    has_tag = any(str(t).startswith("attack.t") for t in broken.get("tags", []))
    assert not (has_condition and has_tag), \
        "broken example unexpectedly passed validation - the gate is not testing anything"
