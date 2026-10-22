"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


SECTIONS = ("zones", "elements", "flows", "threats")
CATEGORIES = ("S", "T", "R", "I", "D", "E")  # STRIDE order
STATUSES = ("open", "mitigated", "accepted")
ENCRYPTED = {"https", "tls", "mtls", "sftp", "ssh"}
ELEMENT_KINDS = {
    "external": "external",
    "external_entity": "external",
    "process": "process",
    "data_store": "data_store",
}


# ---------------------------------------------------------------- helpers
def _items(model, key):
    """The dict entries of a section; anything else is ignored."""
    value = model.get(key) if isinstance(model, dict) else None
    if not isinstance(value, list):
        return []
    return [x for x in value if isinstance(x, dict)]


def _key(value):
    return None if value is None else str(value)


def _ref(item):
    return str(item.get("id"))


def _valid_score(value) -> bool:
    # type(...) is int rejects True/False, 4.0 and "4"
    return type(value) is int and 1 <= value <= 5


def _has_text(value) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _natural(text: str):
    parts = re.split(r"(\d+)", text)
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts if p != "")


def _crossing(model):
    """(flow, source_id, target_id) for flows whose ends sit in different zones."""
    zone_of = {_key(e.get("id")): _key(e.get("zone")) for e in _items(model, "elements")}
    found = []
    for flow in _items(model, "flows"):
        s, t = _key(flow.get("source")), _key(flow.get("target"))
        if s in zone_of and t in zone_of and zone_of[s] != zone_of[t]:
            found.append((flow, s, t))
    return found


# ------------------------------------------------------------------- API
def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, UnicodeDecodeError) as exc:
        raise ModelError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ModelError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelError("top level of the model must be a mapping")
    model = dict(data)
    for section in SECTIONS:
        value = model.get(section)
        if value is None:
            model[section] = []
        elif not isinstance(value, list):
            raise ModelError(f"section '{section}' must be a list")
    return model


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    canon = ELEMENT_KINDS.get(kind) if isinstance(kind, str) else None
    if canon is None and kind in ("data_flow", "flow"):
        canon = "flow"
    if canon is None:
        raise ValueError(f"unknown kind: {kind!r}")
    if canon == "external":
        return {"S", "R"}
    if canon == "process":
        return set(CATEGORIES)
    if canon == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    return {"T", "I", "D"}  # flow


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues: set[Issue] = set()
    zones = _items(model, "zones")
    elements = _items(model, "elements")
    flows = _items(model, "flows")
    threats = _items(model, "threats")

    zone_ids = {_key(z.get("id")) for z in zones}

    # one id space for elements, flows and threats
    counts = Counter(_key(x.get("id")) for x in elements + flows + threats)
    for ident, n in counts.items():
        if ident is not None and n > 1:
            issues.add(Issue(ident, "DUPLICATE_ID", f"id used {n} times in the model"))

    element_ids = set()
    element_kind = {}   # id -> canonical kind (valid kinds only)
    element_log = {}
    for e in elements:
        ref = _ref(e)
        eid = _key(e.get("id"))
        element_ids.add(eid)
        kind = ELEMENT_KINDS.get(e.get("kind")) if isinstance(e.get("kind"), str) else None
        if kind is None:
            issues.add(Issue(ref, "BAD_KIND", f"unknown kind: {e.get('kind')!r}"))
        else:
            element_kind.setdefault(eid, kind)
        element_log.setdefault(eid, e.get("is_log") is True)
        if _key(e.get("zone")) not in zone_ids:
            issues.add(Issue(ref, "UNKNOWN_ZONE", f"zone {e.get('zone')!r} is not defined"))

    flow_ids = {_key(f.get("id")) for f in flows}

    for f in flows:
        ref = _ref(f)
        s, t = _key(f.get("source")), _key(f.get("target"))
        for name, end in (("source", s), ("target", t)):
            if end not in element_ids:
                issues.add(Issue(ref, "UNKNOWN_REF", f"{name} {end!r} is not an element"))
        if s in element_ids and t in element_ids:
            if s == t:
                issues.add(Issue(ref, "INVALID_FLOW", "a flow cannot start and end on the same element"))
            elif s in element_kind and t in element_kind:
                if "process" not in (element_kind[s], element_kind[t]):
                    issues.add(Issue(
                        ref, "INVALID_FLOW",
                        f"{element_kind[s]} to {element_kind[t]}: a process must be on one end"))

    for th in threats:
        ref = _ref(th)
        target = _key(th.get("target"))
        kind, is_log = None, False
        if target in element_ids:
            kind = element_kind.get(target)
            is_log = element_log.get(target, False)
        elif target in flow_ids:
            kind = "flow"
        else:
            issues.add(Issue(ref, "UNKNOWN_REF", f"target {target!r} does not exist"))

        category = th.get("category")
        if not (isinstance(category, str) and category in CATEGORIES):
            issues.add(Issue(ref, "BAD_CATEGORY", f"category {category!r} is not one of S, T, R, I, D, E"))
        elif kind is not None and category not in applicable(kind, is_log=is_log):
            issues.add(Issue(ref, "INAPPLICABLE_CATEGORY", f"{category} does not apply to a {kind}"))

        for field in ("likelihood", "impact"):
            if not _valid_score(th.get(field)):
                issues.add(Issue(ref, "BAD_SCORE", f"{field} must be an integer from 1 to 5"))

        status = th.get("status")
        if not (isinstance(status, str) and status in STATUSES):
            issues.add(Issue(ref, "BAD_STATUS", f"status {status!r} is not open, mitigated or accepted"))
        elif status == "mitigated" and not _has_text(th.get("mitigation")):
            issues.add(Issue(ref, "MISSING_MITIGATION", "mitigated needs a mitigation text"))
        elif status == "accepted" and not _has_text(th.get("justification")):
            issues.add(Issue(ref, "MISSING_JUSTIFICATION", "accepted needs a justification"))

    return sorted(issues)


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    return [_ref(flow) for flow, _s, _t in _crossing(model)]


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = {}
    for e in _items(model, "elements"):
        elements.setdefault(_key(e.get("id")), e)

    scope = {}  # ref -> (kind, is_log)
    for flow, s, t in _crossing(model):
        scope.setdefault(_ref(flow), ("flow", False))
        for end in (s, t):
            kind = ELEMENT_KINDS.get(elements[end].get("kind")) \
                if isinstance(elements[end].get("kind"), str) else None
            if kind is not None:
                scope[end] = (kind, elements[end].get("is_log") is True)

    covered = {
        (_key(th.get("target")), th.get("category"))
        for th in _items(model, "threats")
        if isinstance(th.get("category"), str)
    }

    gaps = []
    for ref, (kind, is_log) in scope.items():
        for cat in applicable(kind, is_log=is_log):
            if (ref, cat) not in covered:
                gaps.append(Gap(ref, cat))
    return sorted(gaps, key=lambda g: (g.ref, CATEGORIES.index(g.category)))


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    findings: set[Issue] = set()
    zone_of = {_key(e.get("id")): _key(e.get("zone")) for e in _items(model, "elements")}
    trust = {_key(z.get("id")): _number(z.get("trust")) for z in _items(model, "zones")}

    for flow, s, t in _crossing(model):
        ref = _ref(flow)
        protocol = flow.get("protocol")
        if not (isinstance(protocol, str) and protocol.lower() in ENCRYPTED):
            findings.add(Issue(ref, "UNENCRYPTED_CROSSING", f"protocol {protocol!r} crosses a zone boundary"))
        source_trust, target_trust = trust.get(zone_of[s]), trust.get(zone_of[t])
        if (source_trust is not None and target_trust is not None
                and target_trust > source_trust and flow.get("authenticated") is not True):
            findings.add(Issue(ref, "UNAUTHENTICATED_INBOUND", "inbound flow to a higher-trust zone is not authenticated"))

    has_i = {
        _key(th.get("target"))
        for th in _items(model, "threats")
        if th.get("category") == "I"
    }
    for e in _items(model, "elements"):
        if e.get("kind") == "data_store" and e.get("holds_pii") is True \
                and _key(e.get("id")) not in has_i:
            findings.add(Issue(_ref(e), "PII_STORE_WITHOUT_I_THREAT", "store holds personal data but has no I threat"))

    return sorted(findings, key=lambda i: (i.ref, i.code))


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    ranked = []
    for th in _items(model, "threats"):
        if th.get("status") != "open":
            continue
        likelihood, impact = th.get("likelihood"), th.get("impact")
        if not (_valid_score(likelihood) and _valid_score(impact)):
            continue
        score = likelihood * impact
        level = "high" if score >= 15 else "medium" if score >= 8 else "low"
        ranked.append((score, impact, RankedThreat(_ref(th), score, level)))
    ranked.sort(key=lambda r: (-r[0], -r[1], _natural(r[2].id)))
    return [r[2] for r in ranked]
