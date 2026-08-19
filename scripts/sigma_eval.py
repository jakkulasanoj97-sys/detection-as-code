"""
sigma_eval.py - a small, dependency-light Sigma matcher.

It supports the subset of Sigma used by this repo's rules:
  - field equality
  - field modifiers: |endswith, |startswith, |contains
  - list values (OR within a field)
  - multiple selection maps (AND across maps in a selection)
  - filter_* blocks combined via: 'selection and not 1 of filter_*'
                              or  'selection and not filter_<name>'

This is intentionally simple and transparent so results are easy to explain: given an
event (a flat dict of str->str) and a rule, does the rule fire? It is NOT a full Sigma
engine and is not meant to replace pySigma for production conversion.
"""
from __future__ import annotations
import yaml
from pathlib import Path


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _match_value(event_val: str, expected, modifier: str | None) -> bool:
    event_val = "" if event_val is None else str(event_val)
    for exp in _as_list(expected):
        exp = str(exp)
        if modifier == "endswith" and event_val.lower().endswith(exp.lower()):
            return True
        if modifier == "startswith" and event_val.lower().startswith(exp.lower()):
            return True
        if modifier == "contains" and exp.lower() in event_val.lower():
            return True
        if modifier is None and event_val.lower() == exp.lower():
            return True
    return False


def _match_map(event: dict, criteria: dict) -> bool:
    """All key/value pairs in a selection map must match (AND)."""
    for key, expected in criteria.items():
        field, _, modifier = key.partition("|")
        modifier = modifier or None
        # case-insensitive field lookup
        event_val = None
        for ek, ev in event.items():
            if ek.lower() == field.lower():
                event_val = ev
                break
        if not _match_value(event_val, expected, modifier):
            return False
    return True


def rule_matches_event(rule: dict, event: dict) -> bool:
    detection = rule.get("detection", {})
    if "selection" not in detection or "condition" not in detection:
        raise ValueError("rule missing 'selection' or 'condition'")

    selection = detection["selection"]
    selection_hit = _match_map(event, selection)
    if not selection_hit:
        return False

    # collect filter blocks
    filters = {k: v for k, v in detection.items() if k.startswith("filter_")}
    for fname, fmap in filters.items():
        if _match_map(event, fmap):
            # any matching filter excludes the event
            return False
    return True


def load_rule(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        # take the first YAML doc (rules with correlation use multi-doc; base rule is first)
        docs = list(yaml.safe_load_all(fh))
    return docs[0]


def evaluate_file(rule: dict, jsonl_path: str | Path) -> int:
    """Return number of events in the JSONL file that the rule fires on."""
    import json
    hits = 0
    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            # flatten one level in case of nested dicts
            flat = {}
            for k, v in event.items():
                flat[k] = v if not isinstance(v, (dict, list)) else str(v)
            if rule_matches_event(rule, flat):
                hits += 1
    return hits
