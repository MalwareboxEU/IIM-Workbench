#!/usr/bin/env python3
"""
iim_stix - bidirectional conversion between IIM and STIX 2.1.

This module is importable as a library. See iim_to_stix.py and stix_to_iim.py
for CLI wrappers.

IIM -> STIX: lossless. Every IIM concept maps to STIX 2.1 objects with
  x_iim_* custom properties preserving IIM-specific semantics.

STIX -> IIM: not lossless. STIX lacks three IIM concepts:
  - chain-scoped role semantics
  - ordered chains
  - infrastructure techniques
  The converter therefore runs an *enrichment workflow*: it extracts what
  structure STIX carries, heuristically infers roles from STIX
  infrastructure_types, and marks every inferred annotation with
  confidence="tentative" and needs_review=true. An analyst must review
  the imported chain before promoting it to higher confidence.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any


ALLOWED_ENTITY_TYPES = {
    "url", "domain", "ip", "file", "hash", "email", "certificate", "asn"
}
ALLOWED_ROLES = {"entry", "redirector", "staging", "payload", "c2"}
ALLOWED_RELATIONS = {
    "download", "redirect", "drops", "execute", "connect",
    "resolves-to", "references", "communicates-with"
}

# STIX infrastructure_types -> IIM role (heuristic, best-effort)
STIX_INFRA_TO_ROLE = {
    "command-and-control":   "c2",
    "botnet":                "c2",
    "hosting-malware":       "staging",
    "hosting-target-lists":  "entry",
    "phishing":              "entry",
    "staging":               "staging",
    "exfiltration":          "c2",
    "anonymization":         "redirector",
    "undisclosed":           "redirector",
    "unknown":               "redirector",
}

# STIX observable object -> IIM entity type
STIX_OBSERVABLE_TO_ENTITY_TYPE = {
    "url":                  "url",
    "domain-name":          "domain",
    "ipv4-addr":            "ip",
    "ipv6-addr":            "ip",
    "file":                 "file",
    "email-addr":           "email",
    "email-message":        "email",
    "x509-certificate":     "certificate",
    "autonomous-system":    "asn",
}


def _stix_uuid(namespace: str, key: str) -> str:
    """Deterministic UUID for round-trippable exports."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"iim:{namespace}:{key}"))


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_pattern_for_entity(ent: dict) -> str:
    """Produce a STIX pattern string for a given IIM entity."""
    etype = ent.get("type", "")
    val = str(ent.get("value", "")).replace("'", "\\'")
    mapping = {
        "url":         f"[url:value = '{val}']",
        "domain":      f"[domain-name:value = '{val}']",
        "ip":          f"[ipv4-addr:value = '{val}']",
        "file":        f"[file:name = '{val}']",
        "hash":        f"[file:hashes.'SHA-256' = '{val}']",
        "email":       f"[email-addr:value = '{val}']",
        "certificate": f"[x509-certificate:hashes.'SHA-256' = '{val}']",
        "asn":         f"[autonomous-system:number = {val}]" if val.isdigit() else f"[autonomous-system:name = '{val}']",
    }
    return mapping.get(etype, f"[unknown:value = '{val}']")


def _stix_infrastructure_type(role: str) -> list[str]:
    return {
        "entry":      ["unknown"],
        "redirector": ["hosting-malware"],
        "staging":    ["hosting-malware", "staging"],
        "payload":    ["hosting-malware"],
        "c2":         ["command-and-control"],
    }.get(role, ["unknown"])


def iim_chain_to_stix(chain: dict, catalog: dict | None = None) -> dict:
    """
    Convert an IIM chain to a STIX 2.1 Bundle.

    The bundle contains:
      - 1 Identity (the workbench as publisher)
      - 1 Grouping wrapping the entire chain with context="iim-chain"
      - N Indicators (one per entity, with STIX pattern strings)
      - N Infrastructure objects (one per role position)
      - M Attack-Patterns (one per unique IIM technique)
      - K Relationships (indicates, uses, related-to)

    All objects use deterministic UUIDv5 based on the chain ID.
    Custom properties (x_iim_*) preserve IIM-specific fields.
    """
    now = _now_utc_iso()
    cid = chain.get("chain_id", "unnamed")
    objects: list[dict] = []
    ref: dict[str, str] = {}
    tech_map = {t["id"]: t for t in (catalog or {}).get("techniques", [])}

    # Identity (publisher)
    ident_id = "identity--" + _stix_uuid("identity", "iim-workbench")
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": ident_id,
        "created": now, "modified": now,
        "name": "IIM Workbench", "identity_class": "system",
    })

    # Entity indicators
    for ent in chain.get("entities", []):
        eid = ent["id"]
        ind_id = "indicator--" + _stix_uuid("indicator", f"{cid}:{eid}")
        ref[f"ind:{eid}"] = ind_id
        indicator_obj = {
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now, "created_by_ref": ident_id,
            "pattern": _stix_pattern_for_entity(ent), "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "x_iim_entity_type": ent["type"],
            "x_iim_entity_id": eid,
            "x_iim_entity_value": ent.get("value"),
        }
        if ent.get("observed_at"):
            indicator_obj["valid_from"] = ent["observed_at"]
        if ent.get("source"):
            indicator_obj["x_iim_source"] = ent["source"]
        if ent.get("evidence"):
            indicator_obj["x_iim_evidence"] = ent["evidence"]
        objects.append(indicator_obj)

    # Infrastructure objects per chain position
    for i, pos in enumerate(chain.get("chain", [])):
        eid = pos["entity_id"]
        role = pos.get("role", "unknown")
        infra_id = "infrastructure--" + _stix_uuid("infrastructure", f"{cid}:pos{i}:{eid}")
        ref[f"infra:{i}"] = infra_id
        ent = next((e for e in chain.get("entities", []) if e["id"] == eid), {})
        name = f"{role.capitalize()} · {ent.get('value', eid)}"
        infra_obj = {
            "type": "infrastructure", "spec_version": "2.1", "id": infra_id,
            "created": now, "modified": now, "created_by_ref": ident_id,
            "name": name,
            "infrastructure_types": _stix_infrastructure_type(role),
            "x_iim_role": role,
            "x_iim_chain_id": cid,
            "x_iim_position": i,
            "x_iim_techniques": pos.get("techniques", []),
            "x_iim_entity_id": eid,
        }
        if pos.get("role_confidence"):
            infra_obj["x_iim_role_confidence"] = pos["role_confidence"]
        if pos.get("technique_confidence"):
            infra_obj["x_iim_technique_confidence"] = pos["technique_confidence"]
        if pos.get("needs_review"):
            infra_obj["x_iim_needs_review"] = True
        if pos.get("review_notes"):
            infra_obj["x_iim_review_notes"] = pos["review_notes"]
        objects.append(infra_obj)

        # Relationship: Indicator -> Infrastructure
        if f"ind:{eid}" in ref:
            objects.append({
                "type": "relationship", "spec_version": "2.1",
                "id": "relationship--" + _stix_uuid("rel", f"{cid}:indicates:{eid}:{i}"),
                "created": now, "modified": now,
                "relationship_type": "indicates",
                "source_ref": ref[f"ind:{eid}"],
                "target_ref": infra_id,
            })

    # Technique attack-patterns
    seen_techs: set[str] = set()
    for pos in chain.get("chain", []):
        for tid in pos.get("techniques", []):
            if tid in seen_techs:
                continue
            seen_techs.add(tid)
            ap_id = "attack-pattern--" + _stix_uuid("technique", tid)
            ref[f"tech:{tid}"] = ap_id
            info = tech_map.get(tid, {})
            objects.append({
                "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                "created": now, "modified": now, "created_by_ref": ident_id,
                "name": info.get("name", tid),
                "description": info.get("description", ""),
                "external_references": [{
                    "source_name": "iim",
                    "external_id": tid,
                    "url": f"https://iim.malwarebox.eu/techniques/{tid}",
                }],
                "x_iim_category": info.get("category", ""),
                "x_iim_technique_id": tid,
            })

    # "uses" relationships: infrastructure -> technique
    for i, pos in enumerate(chain.get("chain", [])):
        for tid in pos.get("techniques", []):
            if f"tech:{tid}" not in ref:
                continue
            objects.append({
                "type": "relationship", "spec_version": "2.1",
                "id": "relationship--" + _stix_uuid("rel", f"{cid}:uses:{i}:{tid}"),
                "created": now, "modified": now,
                "relationship_type": "uses",
                "source_ref": ref[f"infra:{i}"],
                "target_ref": ref[f"tech:{tid}"],
            })

    # Chain flow relationships: infrastructure -> infrastructure
    position_by_entity: dict[str, int] = {}
    for i, pos in enumerate(chain.get("chain", [])):
        position_by_entity[pos["entity_id"]] = i

    for rel in chain.get("relations", []):
        fp = position_by_entity.get(rel.get("from"))
        tp = position_by_entity.get(rel.get("to"))
        if fp is None or tp is None:
            continue
        rel_obj = {
            "type": "relationship", "spec_version": "2.1",
            "id": "relationship--" + _stix_uuid("rel", f"{cid}:flow:{fp}:{tp}:{rel.get('type')}"),
            "created": now, "modified": now,
            "relationship_type": "related-to",
            "source_ref": ref[f"infra:{fp}"],
            "target_ref": ref[f"infra:{tp}"],
            "x_iim_relation_type": rel.get("type"),
        }
        if rel.get("sequence_order") is not None:
            rel_obj["x_iim_sequence_order"] = rel["sequence_order"]
        if rel.get("confidence"):
            rel_obj["x_iim_confidence"] = rel["confidence"]
        if rel.get("observed_at"):
            rel_obj["x_iim_observed_at"] = rel["observed_at"]
        objects.append(rel_obj)

    # Grouping wraps the whole chain
    group_id = "grouping--" + _stix_uuid("grouping", cid)
    group_obj = {
        "type": "grouping", "spec_version": "2.1", "id": group_id,
        "created": now, "modified": now, "created_by_ref": ident_id,
        "name": f"IIM Chain · {cid}",
        "context": "iim-chain",
        "object_refs": [o["id"] for o in objects if o["id"] != ident_id],
        "x_iim_chain_id": cid,
        "x_iim_version": chain.get("iim_version", "1.1"),
    }
    if chain.get("actor_id"):
        group_obj["x_iim_actor_id"] = chain["actor_id"]
    if chain.get("confidence"):
        group_obj["x_iim_confidence"] = chain["confidence"]
    if chain.get("title"):
        group_obj["description"] = chain["title"]
    if chain.get("description"):
        group_obj["description"] = (group_obj.get("description", "") + "\n\n" + chain["description"]).strip()
    objects.insert(1, group_obj)

    return {
        "type": "bundle",
        "id": "bundle--" + _stix_uuid("bundle", cid),
        "objects": objects,
    }


def _entity_from_stix_indicator(indicator: dict) -> dict | None:
    """
        Extract an IIM entity from a STIX Indicator.
        Prefer x_iim_* custom properties if present (round-trip) but the
        value must be non-empty to trust the round-trip. If the producing
        tool didn't include x_iim_entity_value, fall back to pattern parsing.
    """

    rt_id    = indicator.get("x_iim_entity_id")
    rt_type  = indicator.get("x_iim_entity_type")
    rt_value = indicator.get("x_iim_entity_value")
    if rt_id and rt_type and rt_value:
        ent = {"id": rt_id, "type": rt_type, "value": rt_value}
        if indicator.get("valid_from"): ent["observed_at"] = indicator["valid_from"]
        if indicator.get("x_iim_source"): ent["source"] = indicator["x_iim_source"]
        if indicator.get("x_iim_evidence"): ent["evidence"] = indicator["x_iim_evidence"]
        return ent

    # Partial round-trip or naive import: parse the STIX pattern for the value
    pattern = indicator.get("pattern", "")
    parsed = _parse_stix_pattern(pattern)
    if not parsed:
        return None

    stix_obj_type, value = parsed
    iim_type = rt_type or STIX_OBSERVABLE_TO_ENTITY_TYPE.get(stix_obj_type)
    if not iim_type:
        return None

    # Use round-trip ID if available, otherwise synthesize a short ID
    if rt_id:
        short_id = rt_id
    else:
        ind_id = indicator.get("id", "")
        short_id = "e_" + (ind_id.split("--")[-1][:8] if "--" in ind_id
                           else str(abs(hash(pattern)) % 10000))

    ent = {
        "id":    short_id,
        "type":  iim_type,
        "value": value,
    }
    if indicator.get("valid_from"):
        ent["observed_at"] = indicator["valid_from"]
    if indicator.get("x_iim_source") or indicator.get("created_by_ref"):
        ent["source"] = indicator.get("x_iim_source") or indicator["created_by_ref"]
    return ent


def _parse_stix_pattern(pattern: str) -> tuple[str, str] | None:
    """
    Parse a simple STIX pattern string like `[url:value = 'https://x']`.
    Returns (stix_object_type, value) or None.

    This is a best-effort parser for common single-comparison patterns.
    Complex patterns (AND/OR/FOLLOWEDBY/NOT) are not supported at v1.1;
    callers should preserve the original pattern and flag the entity for
    manual review.
    """
    if not isinstance(pattern, str):
        return None
    # Strip outer brackets and whitespace
    p = pattern.strip().strip("[]").strip()
    # Match: <type>:<prop> = '<value>'  or  <type>:<prop> = <value>
    m = re.match(r"^([a-z0-9\-]+):([a-zA-Z0-9._'-]+)\s*=\s*['\"]?([^'\"]+)['\"]?$", p)
    if not m:
        return None
    obj_type, _prop, value = m.group(1), m.group(2), m.group(3)
    return obj_type, value


def _role_from_infrastructure_types(infra_types: list[str]) -> tuple[str, str]:
    """
    Heuristically pick an IIM role from STIX infrastructure_types.
    Returns (role, confidence).
    """
    if not infra_types:
        return "redirector", "tentative"
    # First mapped value wins
    for t in infra_types:
        if t in STIX_INFRA_TO_ROLE:
            return STIX_INFRA_TO_ROLE[t], "tentative"
    return "redirector", "tentative"


def _relation_type_from_stix(stix_rel_type: str, iim_hint: str | None) -> tuple[str, str]:
    """
    Derive IIM relation type from STIX relationship.
    Returns (relation_type, confidence).
    """
    if iim_hint and iim_hint in ALLOWED_RELATIONS:
        return iim_hint, "likely"
    mapping = {
        "communicates-with": "connect",
        "downloads":         "download",
        "drops":             "drops",
        "exploits":          "execute",
        "hosts":             "references",
        "related-to":        "communicates-with",
        "uses":              "connect",
    }
    return mapping.get(stix_rel_type, "communicates-with"), "tentative"


def stix_to_iim_chain(bundle: dict, chain_id: str | None = None) -> dict:
    """
    Convert a STIX 2.1 Bundle to an IIM chain (enrichment workflow).

    The converter:
      1. Prefers round-trip data (x_iim_* custom properties) when available
      2. Falls back to heuristic inference from STIX infrastructure_types
         and attack-pattern external_references
      3. Marks every heuristically-derived field with confidence="tentative"
         and flags the chain with needs_review=true and
         import_source="stix-2.1"

    Callers must review the imported chain before promoting to higher
    confidence.
    """
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("Input is not a STIX 2.1 bundle")

    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if o.get("id")}

    # Round-trip detection: look for Grouping with context=iim-chain
    grouping = next(
        (o for o in objects if o.get("type") == "grouping" and o.get("context") == "iim-chain"),
        None
    )
    is_roundtrip = grouping is not None and grouping.get("x_iim_chain_id")
    derived_chain_id = (
        chain_id
        or (grouping.get("x_iim_chain_id") if grouping else None)
        or f"imported-{_stix_uuid('import', bundle.get('id', 'unknown'))[:8]}"
    )

    # Collect entities from Indicators
    entities: list[dict] = []
    indicator_to_entity_id: dict[str, str] = {}
    for o in objects:
        if o.get("type") != "indicator":
            continue
        ent = _entity_from_stix_indicator(o)
        if ent:
            entities.append(ent)
            indicator_to_entity_id[o["id"]] = ent["id"]

    # Deduplicate entities by (type, value)
    seen_keys: set[tuple[str, str]] = set()
    unique_entities: list[dict] = []
    id_remap: dict[str, str] = {}
    for ent in entities:
        key = (ent["type"], ent["value"])
        if key in seen_keys:
            existing = next(e for e in unique_entities if (e["type"], e["value"]) == key)
            id_remap[ent["id"]] = existing["id"]
            continue
        seen_keys.add(key)
        unique_entities.append(ent)
    # Apply remap
    for ind_id, eid in indicator_to_entity_id.items():
        if eid in id_remap:
            indicator_to_entity_id[ind_id] = id_remap[eid]

    # Collect chain positions from Infrastructure objects
    infra_objects = [o for o in objects if o.get("type") == "infrastructure"]

    # If round-trip, respect x_iim_position ordering
    if is_roundtrip and all("x_iim_position" in o for o in infra_objects):
        infra_objects.sort(key=lambda o: o["x_iim_position"])

    # Map infrastructure -> entity_id via "indicates" relationships
    infra_to_entity: dict[str, str] = {}
    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "indicates":
            continue
        src = o.get("source_ref", "")
        tgt = o.get("target_ref", "")
        if src in indicator_to_entity_id and tgt.startswith("infrastructure--"):
            infra_to_entity[tgt] = indicator_to_entity_id[src]

    # Map infrastructure -> techniques via "uses" relationships
    infra_to_techniques: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
            continue
        src = o.get("source_ref", "")
        tgt = o.get("target_ref", "")
        if not (src.startswith("infrastructure--") and tgt.startswith("attack-pattern--")):
            continue
        ap = by_id.get(tgt)
        if not ap:
            continue
        # Try round-trip first, then external_references
        tid = ap.get("x_iim_technique_id")
        if not tid:
            for ext in ap.get("external_references", []):
                if ext.get("source_name") == "iim" and ext.get("external_id"):
                    tid = ext["external_id"]
                    break
        if tid and re.match(r"^IIM-T\d{3}$", tid):
            infra_to_techniques.setdefault(src, []).append(tid)

    # Build chain positions
    chain_positions: list[dict] = []
    infra_id_to_position_index: dict[str, int] = {}
    needs_review_flags: list[bool] = []

    for i, infra in enumerate(infra_objects):
        infra_id = infra["id"]
        # Prefer round-trip x_iim_role
        if infra.get("x_iim_role"):
            role = infra["x_iim_role"]
            role_conf = infra.get("x_iim_role_confidence", "likely")
            role_inferred = False
        else:
            role, role_conf = _role_from_infrastructure_types(
                infra.get("infrastructure_types", [])
            )
            role_inferred = True

        # Techniques: prefer round-trip x_iim_techniques, else from uses relationships
        techniques = infra.get("x_iim_techniques") or infra_to_techniques.get(infra_id, [])
        tech_conf = (
            infra.get("x_iim_technique_confidence", "likely")
            if infra.get("x_iim_techniques") else "tentative"
        )

        entity_id = (
            infra.get("x_iim_entity_id")
            or infra_to_entity.get(infra_id)
            or f"unknown_e{i}"
        )

        pos = {
            "entity_id": entity_id,
            "role":      role,
            "techniques": techniques,
        }
        if role_inferred or not is_roundtrip:
            pos["role_confidence"]      = role_conf
            pos["technique_confidence"] = tech_conf
            pos["needs_review"]         = True
            pos["review_notes"]         = "Role and/or techniques inferred from STIX import. Please verify."
            needs_review_flags.append(True)
        else:
            needs_review_flags.append(False)

        chain_positions.append(pos)
        infra_id_to_position_index[infra_id] = i

    # Build relations from infrastructure -> infrastructure relationships
    relations: list[dict] = []
    for o in objects:
        if o.get("type") != "relationship":
            continue
        src = o.get("source_ref", "")
        tgt = o.get("target_ref", "")
        if not (src.startswith("infrastructure--") and tgt.startswith("infrastructure--")):
            continue
        src_idx = infra_id_to_position_index.get(src)
        tgt_idx = infra_id_to_position_index.get(tgt)
        if src_idx is None or tgt_idx is None:
            continue
        src_pos = chain_positions[src_idx]
        tgt_pos = chain_positions[tgt_idx]
        rel_type, rel_conf = _relation_type_from_stix(
            o.get("relationship_type", ""),
            o.get("x_iim_relation_type")
        )
        rel_obj = {
            "from": src_pos["entity_id"],
            "to":   tgt_pos["entity_id"],
            "type": rel_type,
        }
        if o.get("x_iim_sequence_order") is not None:
            rel_obj["sequence_order"] = o["x_iim_sequence_order"]
        if rel_conf != "likely":
            rel_obj["confidence"] = rel_conf
        if o.get("x_iim_observed_at"):
            rel_obj["observed_at"] = o["x_iim_observed_at"]
        relations.append(rel_obj)

    if not relations and len(chain_positions) >= 2:
        for i in range(len(chain_positions) - 1):
            relations.append({
                "from": chain_positions[i]["entity_id"],
                "to":   chain_positions[i+1]["entity_id"],
                "type": "communicates-with",
                "sequence_order": i + 1,
                "confidence":     "tentative",
            })
        needs_review_flags.append(True)

    # Pull top-level metadata from Grouping if available
    chain_obj = {
        "iim_version":   "1.1",
        "chain_id":      derived_chain_id,
        "entities":      unique_entities,
        "chain":         chain_positions,
        "relations":     relations,
        "import_source": "stix-2.1",
    }

    if grouping:
        if grouping.get("description"):
            chain_obj["description"] = grouping["description"]
        if grouping.get("x_iim_actor_id"):
            chain_obj["actor_id"] = grouping["x_iim_actor_id"]
        if grouping.get("x_iim_confidence"):
            chain_obj["confidence"] = grouping["x_iim_confidence"]

    # If anything was heuristic, flag the chain
    if any(needs_review_flags) or not is_roundtrip:
        chain_obj["confidence"]   = chain_obj.get("confidence", "tentative")
        chain_obj["needs_review"] = True

    return chain_obj


def import_report(bundle: dict, chain: dict) -> dict:
    """
    Produce a structured report of what the STIX->IIM import did:
    counts, round-trip vs. heuristic detection, items that need review.
    """
    objects = bundle.get("objects", [])
    types_in_bundle: dict[str, int] = {}
    for o in objects:
        t = o.get("type", "unknown")
        types_in_bundle[t] = types_in_bundle.get(t, 0) + 1

    grouping = next(
        (o for o in objects if o.get("type") == "grouping" and o.get("context") == "iim-chain"),
        None
    )
    round_trip = grouping is not None and bool(grouping.get("x_iim_chain_id"))

    review_count = sum(1 for p in chain.get("chain", []) if p.get("needs_review"))

    return {
        "round_trip_detected": round_trip,
        "stix_bundle_id":      bundle.get("id"),
        "stix_object_counts":  types_in_bundle,
        "iim_chain_id":        chain.get("chain_id"),
        "iim_entity_count":    len(chain.get("entities", [])),
        "iim_position_count":  len(chain.get("chain", [])),
        "iim_relation_count":  len(chain.get("relations", [])),
        "positions_needing_review": review_count,
        "chain_needs_review":       chain.get("needs_review", False),
        "chain_confidence":         chain.get("confidence"),
        "import_source":            chain.get("import_source"),
        "warnings": _collect_warnings(bundle, chain),
    }


def _collect_warnings(bundle: dict, chain: dict) -> list[str]:
    """Return a list of human-readable warnings about the import."""
    warnings: list[str] = []
    objects = bundle.get("objects", [])

    # Check for unsupported STIX patterns
    unsupported_patterns = 0
    for o in objects:
        if o.get("type") != "indicator":
            continue
        pattern = o.get("pattern", "")
        if pattern and not _parse_stix_pattern(pattern) and not o.get("x_iim_entity_id"):
            unsupported_patterns += 1
    if unsupported_patterns:
        warnings.append(
            f"{unsupported_patterns} indicator(s) had complex STIX patterns that "
            "could not be parsed; those entities were skipped. Review the source bundle."
        )

    # Check for orphaned infrastructure (no entity association)
    orphan_positions = sum(
        1 for p in chain.get("chain", [])
        if str(p.get("entity_id", "")).startswith("unknown_")
    )
    if orphan_positions:
        warnings.append(
            f"{orphan_positions} chain position(s) could not be linked to an entity "
            "and carry placeholder IDs. Review and correct before publishing."
        )

    # Check for missing relations
    if chain.get("chain") and not chain.get("relations"):
        warnings.append(
            "No relations were reconstructed from the bundle. The chain has positions "
            "but no declared flow between them."
        )
    elif any(r.get("type") == "communicates-with" and r.get("confidence") == "tentative"
             for r in chain.get("relations", [])):
        warnings.append(
            "Some relations were synthesized as linear flow from position order "
            "because no infrastructure-to-infrastructure relationships existed in the bundle."
        )

    # Check for low technique coverage
    total_positions = len(chain.get("chain", []))
    positions_with_techniques = sum(
        1 for p in chain.get("chain", []) if p.get("techniques")
    )
    if total_positions > 0 and positions_with_techniques == 0:
        warnings.append(
            "No IIM techniques were recovered from the bundle. Techniques must be "
            "added manually after import."
        )

    return warnings

__all__ = [
    "iim_chain_to_stix",
    "stix_to_iim_chain",
    "import_report",
]


if __name__ == "__main__":

    sample_chain = {
        "iim_version": "1.1",
        "chain_id": "self-test",
        "entities": [
            {"id": "e1", "type": "url", "value": "https://x.example"},
            {"id": "e2", "type": "domain", "value": "c2.example"}
        ],
        "chain": [
            {"entity_id": "e1", "role": "entry", "techniques": ["IIM-T019"]},
            {"entity_id": "e2", "role": "c2", "techniques": ["IIM-T008"]}
        ],
        "relations": [
            {"from": "e1", "to": "e2", "type": "connect", "sequence_order": 1}
        ]
    }
    bundle = iim_chain_to_stix(sample_chain)
    print(f"IIM -> STIX: {len(bundle['objects'])} objects")
    roundtrip = stix_to_iim_chain(bundle)
    print(f"STIX -> IIM: {len(roundtrip['entities'])} entities, "
          f"{len(roundtrip['chain'])} positions, "
          f"{len(roundtrip['relations'])} relations")
    report = import_report(bundle, roundtrip)
    print(f"Round-trip detected: {report['round_trip_detected']}")
