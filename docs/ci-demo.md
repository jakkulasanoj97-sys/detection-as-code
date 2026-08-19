# CI Gate Demonstration

This shows the pipeline blocking a bad detection — the part worth talking through in an
interview.

## Passing state

With the shipped rules, the gate is green:

```
$ pytest tests/ -q
13 passed
```

## Introduce a broken rule

`sigma/_broken_example.yml` is malformed on purpose: it has no `detection.condition` and
no MITRE ATT&CK tag. Rename a copy to a shipped name (so the tests pick it up) and run:

```
$ cp sigma/_broken_example.yml sigma/kerberoasting_BROKEN.yml
$ pytest tests/ -q
FAILED tests/test_detections.py::test_rule_structure[kerberoasting_BROKEN.yml]
FAILED tests/test_detections.py::test_rule_has_attack_tag[kerberoasting_BROKEN.yml]
2 failed, 13 passed
```

Non-zero exit code -> GitHub Actions marks the check failed -> the pull request is blocked
from merging. Remove the broken rule and the gate goes green again.

## Why this matters

Without the gate, a rule with a broken condition or a missing benign filter can ship
straight to the SIEM and either miss attacks or flood the SOC with false positives. The
gate makes "does this detection actually work?" a merge requirement, not a post-incident
discovery.
