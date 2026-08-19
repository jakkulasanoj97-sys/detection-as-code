# Detection-as-Code Pipeline

Detections treated like software: every rule has a single source of truth, automated
tests, portable generated output, and a CI gate that blocks bad detections from merging.

Sigma is the source of truth. KQL (Microsoft Sentinel) and SPL (Splunk) are **generated**,
not hand-maintained — one rule definition instead of three copies that drift apart.

## The pipeline

```
        Sigma rule (source of truth)
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   pytest gate         convert.py
   ├─ structure        ├─ KQL (Sentinel)
   ├─ ATT&CK tag       └─ SPL (Splunk)
   ├─ true positive
   └─ true negative
                  │
             GitHub Actions
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
     PASS → merge       FAIL → blocked
```

## What the CI gate checks

Every push and pull request runs `pytest`, which enforces four things per rule:

1. **Structure** — valid YAML with all required fields and a `detection.condition`.
2. **ATT&CK tag** — every rule carries a MITRE technique tag (`attack.tXXXX`).
3. **True positive** — the rule fires on its known-malicious fixture.
4. **True negative** — the rule stays silent on benign data (no false positives).

A rule that fails any check blocks the merge. `sigma/_broken_example.yml` is intentionally
malformed to prove the gate works — see `docs/ci-demo.md`.

## Why true-negative tests matter

Firing on an attack is easy. The benign fixtures prove the rules *don't* fire on normal
activity that looks superficially similar:

- Kerberoasting rule ignores machine-account and `krbtgt` service ticket requests.
- DCSync rule ignores replication by domain controllers and the Entra Connect sync account.
- LSASS rule ignores `wininit.exe` and Windows Defender reading LSASS.

A detection that can't tell an attack from routine admin behavior is noise. These tests
make that distinction executable.

## Layout

```
detection-as-code/
├── sigma/                    # source-of-truth rules (+ _broken_example.yml demo)
├── generated/
│   ├── kql/                  # generated Sentinel queries
│   └── spl/                  # generated Splunk queries
├── tests/
│   ├── test_detections.py    # the CI gate
│   └── fixtures/
│       ├── malicious/        # rule must fire
│       └── benign/           # rule must stay quiet
├── scripts/
│   ├── sigma_eval.py         # transparent Sigma matcher
│   └── convert.py            # Sigma -> KQL / SPL
└── .github/workflows/detection-ci.yml
```

## Run locally

```bash
pip install -r requirements.txt
pytest tests/ -v          # run the gate
python scripts/convert.py # regenerate KQL/SPL from Sigma
```

## Note on the converter

`convert.py` handles the field-equality subset used by these rules to keep CI fast and
dependency-light. For broader coverage, swap in [pySigma / sigma-cli](https://github.com/SigmaHQ/sigma-cli)
with the Sentinel and Splunk backends — the repo structure is designed to accommodate that.

## Author

Sanoj J — detection engineering, security automation, identity threat detection.
