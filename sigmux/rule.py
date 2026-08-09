"""Parsing a Sigma rule's YAML into a small AST."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from .ast_nodes import And, FieldMatch, Node, Or
from .condition_parser import parse_condition


def _parse_field_key(key: str):
    """Split 'CommandLine|contains|all' into (field, modifier, require_all)."""
    parts = key.split("|")
    field_name = parts[0]
    mods = parts[1:]
    modifier = "eq"
    require_all = False
    for m in mods:
        if m in ("contains", "startswith", "endswith", "re"):
            modifier = m
        elif m == "all":
            require_all = True
        # Unsupported modifiers (base64, cidr, ...) fall back to 'eq' rather
        # than raising, so a rule using them still converts -- just not
        # perfectly. See README "Known limitations".
    return field_name, modifier, require_all


def _infer_modifier(modifier: str, value: str):
    """Upgrade a bare wildcard value (e.g. '*evil*') to contains/startswith/endswith."""
    if modifier != "eq":
        return modifier, value
    starts = value.startswith("*")
    ends = value.endswith("*") and len(value) > 1
    if starts and ends and len(value) > 1:
        return "contains", value[1:-1]
    if ends and not starts:
        return "startswith", value[:-1]
    if starts and not ends:
        return "endswith", value[1:]
    return "eq", value


def _field_terms(key: str, raw_value: Any) -> Node:
    field_name, modifier, require_all = _parse_field_key(key)
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    matches: List[Node] = []
    for v in values:
        mod, val = _infer_modifier(modifier, str(v))
        matches.append(FieldMatch(field_name, mod, val))
    if len(matches) == 1:
        return matches[0]
    return And(matches) if require_all else Or(matches)


def parse_selection(value: Any) -> Node:
    """Turn one 'detection' map entry into an AST node.

    A selection is either a field->value(s) map (fields are ANDed, list
    values are ORed unless the '|all' modifier is present), or a list of
    such maps (ORed together), or a bare list of keyword strings (Sigma's
    free-text 'keywords' detection style).
    """
    if isinstance(value, dict):
        terms = [_field_terms(k, v) for k, v in value.items()]
        return terms[0] if len(terms) == 1 else And(terms)
    if isinstance(value, list):
        if all(isinstance(item, dict) for item in value):
            branches = [parse_selection(item) for item in value]
            return branches[0] if len(branches) == 1 else Or(branches)
        matches = [FieldMatch("_raw", "contains", str(item)) for item in value]
        return matches[0] if len(matches) == 1 else Or(matches)
    raise ValueError(f"Unsupported selection shape: {value!r}")


@dataclass
class SigmaRule:
    title: str
    id: Optional[str]
    status: Optional[str]
    description: Optional[str]
    level: Optional[str]
    logsource: Dict[str, str]
    selections: Dict[str, Node]
    condition_text: str
    ast: Node
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, text: str) -> "SigmaRule":
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("Sigma rule YAML must be a mapping at the top level")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SigmaRule":
        detection = data.get("detection")
        if not isinstance(detection, dict):
            raise ValueError("Sigma rule is missing a 'detection' block")
        condition_text = detection.get("condition")
        if not condition_text:
            raise ValueError("Sigma rule is missing 'detection.condition'")

        selections = {
            name: parse_selection(value)
            for name, value in detection.items()
            if name != "condition"
        }
        ast = parse_condition(condition_text, selections)

        return cls(
            title=data.get("title", "Untitled rule"),
            id=data.get("id"),
            status=data.get("status"),
            description=data.get("description"),
            level=data.get("level"),
            logsource=data.get("logsource") or {},
            selections=selections,
            condition_text=condition_text,
            ast=ast,
            tags=data.get("tags") or [],
            raw=data,
        )
