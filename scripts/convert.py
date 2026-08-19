"""
convert.py - generate portable queries from the Sigma source of truth.

Sigma is the single source of truth; KQL (Sentinel) and SPL (Splunk) are generated
artifacts. This keeps one rule definition instead of three hand-maintained copies.

For a production pipeline you would use pySigma (sigma-cli) with the Microsoft 365
Defender and Splunk backends. To keep this repo dependency-light and CI-fast, this
script performs the conversion for the field-equality subset used by these rules and
writes the results into generated/kql and generated/spl.

Usage:
  python scripts/convert.py            # write generated queries
  python scripts/convert.py --check    # verify each rule converts without error (CI)
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "sigma"
OUT_KQL = ROOT / "generated" / "kql"
OUT_SPL = ROOT / "generated" / "spl"


def load_rule(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return list(yaml.safe_load_all(fh))[0]


def _kql_clause(field: str, expected) -> str:
    field_name, _, mod = field.partition("|")
    vals = expected if isinstance(expected, list) else [expected]
    parts = []
    for v in vals:
        if mod == "endswith":
            parts.append(f'{field_name} endswith "{v}"')
        elif mod == "startswith":
            parts.append(f'{field_name} startswith "{v}"')
        elif mod == "contains":
            parts.append(f'{field_name} contains "{v}"')
        else:
            parts.append(f'{field_name} == "{v}"')
    return "(" + " or ".join(parts) + ")" if len(parts) > 1 else parts[0]


def _spl_clause(field: str, expected) -> str:
    field_name, _, mod = field.partition("|")
    vals = expected if isinstance(expected, list) else [expected]
    parts = []
    for v in vals:
        if mod in ("endswith", "contains"):
            parts.append(f'{field_name}="*{v}"' if mod == "endswith" else f'{field_name}="*{v}*"')
        elif mod == "startswith":
            parts.append(f'{field_name}="{v}*"')
        else:
            parts.append(f'{field_name}="{v}"')
    return "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]


def convert(rule: dict) -> tuple[str, str]:
    detection = rule["detection"]
    selection = detection["selection"]
    kql_parts = [_kql_clause(k, v) for k, v in selection.items()]
    spl_parts = [_spl_clause(k, v) for k, v in selection.items()]

    # negate filters
    for fname, fmap in detection.items():
        if fname.startswith("filter_"):
            for k, v in fmap.items():
                kql_parts.append("not(" + _kql_clause(k, v) + ")")
                spl_parts.append("NOT " + _spl_clause(k, v))

    title = rule.get("title", "detection")
    kql = f"// {title}\nSecurityEvent\n| where " + "\n| where ".join(kql_parts)
    spl = f'`comment("{title}")`\nindex=* source="WinEventLog:Security" ' + " ".join(spl_parts)
    return kql, spl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify conversion only, write nothing")
    args = ap.parse_args()

    rules = sorted(p for p in SIGMA_DIR.glob("*.yml") if not p.name.startswith("_"))
    OUT_KQL.mkdir(parents=True, exist_ok=True)
    OUT_SPL.mkdir(parents=True, exist_ok=True)

    errors = 0
    for path in rules:
        try:
            rule = load_rule(path)
            kql, spl = convert(rule)
            if not args.check:
                (OUT_KQL / f"{path.stem}.kql").write_text(kql + "\n")
                (OUT_SPL / f"{path.stem}.spl").write_text(spl + "\n")
            print(f"[ok] {path.name}")
        except Exception as e:  # noqa: BLE001
            errors += 1
            print(f"[FAIL] {path.name}: {e}")

    if errors:
        print(f"{errors} rule(s) failed to convert")
        sys.exit(1)
    print("all rules converted")


if __name__ == "__main__":
    main()
