#!/usr/bin/env python3
"""
IIM Workbench local tool for building, validating, and exporting
IIM chains, patterns, and feeds.

Usage:
    python iim_workbench.py                    # start on http://127.0.0.1:5000
    python iim_workbench.py --port 8080
    python iim_workbench.py --validate chain.json
    python iim_workbench.py --stix chain.json

The workbench loads the technique catalog from ./techniques/iim-techniques-v1.0.json
or from the path given by IIM_CATALOG environment variable.

Author:       Robin Dost
Reference:    https://iim.malwarebox.eu
Web Version:  https://workbench.iim.malwarebox.eu
Last Update:  05/03/26

"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from flask import Flask, Response, jsonify, render_template_string, request
except ImportError:
    print("Error: Flask is required. Install with:  pip install flask", file=sys.stderr)
    sys.exit(1)

try:
    from iim_stix import (
        iim_chain_to_stix as _lib_iim_chain_to_stix,
        stix_to_iim_chain as _stix_to_iim_chain,
        import_report as _import_report,
    )
    HAS_STIX_IMPORT = True
except ImportError:
    HAS_STIX_IMPORT = False
    _lib_iim_chain_to_stix = None



VERSION = "0.1.0"
DEFAULT_CATALOG_PATH = "techniques/iim-techniques-v1.0.json"
ALLOWED_ENTITY_TYPES = {
    "url", "domain", "ip", "file", "hash", "email", "certificate", "asn"
}
ALLOWED_ROLES = {"entry", "redirector", "staging", "payload", "c2"}
ALLOWED_RELATIONS = {
    "download", "redirect", "drops", "execute", "connect",
    "resolves-to", "references", "communicates-with"
}
ALLOWED_MATCH_SEMANTICS = {"strict", "structural", "fuzzy"}
ALLOWED_CONFIDENCE = {"confirmed", "likely", "tentative"}


def load_catalog(path: str | None = None) -> dict:
    """Load the technique catalog. Falls back to an embedded minimal version if missing."""
    search_paths = []
    if path:
        search_paths.append(Path(path))
    if os.environ.get("IIM_CATALOG"):
        search_paths.append(Path(os.environ["IIM_CATALOG"]))
    search_paths.extend([
        Path(DEFAULT_CATALOG_PATH),
        Path("iim-techniques-v1.0.json"),
        Path(__file__).parent / DEFAULT_CATALOG_PATH,
        Path(__file__).parent / "iim-techniques-v1.0.json",
    ])

    for p in search_paths:
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                print(f"[catalog] loaded from {p.resolve()}", file=sys.stderr)
                return data
            except (json.JSONDecodeError, OSError) as e:
                print(f"[catalog] failed to load {p}: {e}", file=sys.stderr)

    print(
        "[catalog] NOT FOUND - running with embedded minimal catalog. "
        "Provide the full catalog via --catalog or IIM_CATALOG env var.",
        file=sys.stderr
    )
    return _embedded_minimal_catalog()


def _embedded_minimal_catalog() -> dict:
    """Fallback catalog shell so the app boots even without the JSON file."""
    return {
        "spec_version": "1.0",
        "catalog_version": "1.0.0-minimal",
        "categories": {
            "hosting":     {"label": "Hosting",     "description": "Where infrastructure lives.",      "code": "H"},
            "resolution":  {"label": "Resolution",  "description": "How names are resolved.",         "code": "R"},
            "routing":     {"label": "Routing",     "description": "How traffic flows.",              "code": "X"},
            "gating":      {"label": "Gating",      "description": "Who receives what response.",     "code": "G"},
            "composition": {"label": "Composition", "description": "How artifacts are packaged.",     "code": "C"},
        },
        "techniques": [],
        "technique_index": {"by_category": {}, "total_count": 0},
    }

class Validator:
    def __init__(self, catalog: dict):
        self.catalog = catalog
        self.technique_ids = {t["id"] for t in catalog.get("techniques", [])}

    def validate_chain(self, chain: dict) -> dict:
        errors: list[dict] = []
        warnings: list[dict] = []

        def err(path: str, msg: str): errors.append({"path": path, "message": msg})
        def warn(path: str, msg: str): warnings.append({"path": path, "message": msg})

        # Top-level required fields
        for field in ("iim_version", "chain_id", "entities", "chain", "relations"):
            if field not in chain:
                err(f"$.{field}", f"Missing required field: {field}")

        if errors:
            return {"valid": False, "errors": errors, "warnings": warnings}

        # chain_id format
        cid = str(chain.get("chain_id", ""))
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{2,127}$", cid):
            err("$.chain_id", "chain_id must be 3-128 chars, alphanumeric/./_/- only")

        # Entities
        entities = chain.get("entities", [])
        entity_ids: set[str] = set()
        if not isinstance(entities, list) or not entities:
            err("$.entities", "entities must be a non-empty array")
        else:
            for i, ent in enumerate(entities):
                base = f"$.entities[{i}]"
                if not isinstance(ent, dict):
                    err(base, "entity must be an object"); continue
                if "id" not in ent: err(f"{base}.id", "missing id")
                elif ent["id"] in entity_ids: err(f"{base}.id", f"duplicate entity id: {ent['id']}")
                else: entity_ids.add(ent["id"])
                if "type" not in ent: err(f"{base}.type", "missing type")
                elif ent["type"] not in ALLOWED_ENTITY_TYPES:
                    err(f"{base}.type", f"type '{ent['type']}' not in {sorted(ALLOWED_ENTITY_TYPES)}")
                if "value" not in ent or not str(ent.get("value", "")).strip():
                    err(f"{base}.value", "missing or empty value")

        # Chain positions
        chain_positions = chain.get("chain", [])
        if not isinstance(chain_positions, list) or not chain_positions:
            err("$.chain", "chain must be a non-empty array")
        else:
            seen_entity_at_position = []
            for i, pos in enumerate(chain_positions):
                base = f"$.chain[{i}]"
                if not isinstance(pos, dict):
                    err(base, "chain position must be an object"); continue
                eid = pos.get("entity_id")
                if not eid: err(f"{base}.entity_id", "missing entity_id")
                elif eid not in entity_ids:
                    err(f"{base}.entity_id", f"entity_id '{eid}' does not exist in entities")
                role = pos.get("role")
                if not role: err(f"{base}.role", "missing role")
                elif role not in ALLOWED_ROLES:
                    err(f"{base}.role", f"role '{role}' not in {sorted(ALLOWED_ROLES)}")
                techs = pos.get("techniques", [])
                if not isinstance(techs, list):
                    err(f"{base}.techniques", "techniques must be an array")
                else:
                    for j, t in enumerate(techs):
                        if not re.match(r"^IIM-T\d{3}$", str(t)):
                            err(f"{base}.techniques[{j}]", f"invalid technique id format: {t}")
                        elif self.technique_ids and t not in self.technique_ids:
                            warn(f"{base}.techniques[{j}]", f"technique {t} not in loaded catalog")
                seen_entity_at_position.append(eid)

            # Role ordering sanity check (warning only)
            roles_seen = [p.get("role") for p in chain_positions]
            if "entry" in roles_seen and roles_seen.index("entry") != 0:
                warn("$.chain", "'entry' role typically appears at position 0")

        # Relations
        relations = chain.get("relations", [])
        if not isinstance(relations, list):
            err("$.relations", "relations must be an array")
        else:
            seq_orders = []
            for i, rel in enumerate(relations):
                base = f"$.relations[{i}]"
                if not isinstance(rel, dict):
                    err(base, "relation must be an object"); continue
                for field in ("from", "to", "type"):
                    if field not in rel: err(f"{base}.{field}", f"missing {field}")
                if rel.get("from") and rel["from"] not in entity_ids:
                    err(f"{base}.from", f"unknown entity '{rel['from']}'")
                if rel.get("to") and rel["to"] not in entity_ids:
                    err(f"{base}.to", f"unknown entity '{rel['to']}'")
                rtype = rel.get("type")
                if rtype and rtype not in ALLOWED_RELATIONS:
                    warn(f"{base}.type", f"relation type '{rtype}' is non-standard (allowed: {sorted(ALLOWED_RELATIONS)})")
                if "sequence_order" in rel:
                    so = rel["sequence_order"]
                    if not isinstance(so, int):
                        err(f"{base}.sequence_order", "must be integer")
                    else:
                        seq_orders.append(so)
            if seq_orders and len(seq_orders) != len(set(seq_orders)):
                warn("$.relations", "duplicate sequence_order values detected")

        # Confidence field (optional)
        if "confidence" in chain and chain["confidence"] not in ALLOWED_CONFIDENCE:
            err("$.confidence", f"confidence must be one of {sorted(ALLOWED_CONFIDENCE)}")

        return {"valid": not errors, "errors": errors, "warnings": warnings}

    def validate_pattern(self, pattern: dict) -> dict:
        errors: list[dict] = []
        warnings: list[dict] = []
        def err(p, m): errors.append({"path": p, "message": m})
        def warn(p, m): warnings.append({"path": p, "message": m})

        for field in ("pattern_id", "name", "iim_version", "shape", "relations"):
            if field not in pattern:
                err(f"$.{field}", f"missing required field: {field}")
        if errors:
            return {"valid": False, "errors": errors, "warnings": warnings}

        pid = str(pattern.get("pattern_id", ""))
        if not re.match(r"^[A-Z]{2,6}-F-\d{4}$", pid):
            warn("$.pattern_id", "pattern_id should follow <PREFIX>-F-#### format (e.g. MB-F-0023)")

        shape = pattern.get("shape", [])
        if not isinstance(shape, list) or not shape:
            err("$.shape", "shape must be a non-empty array")
        else:
            for i, pos in enumerate(shape):
                base = f"$.shape[{i}]"
                if "role" not in pos:
                    err(f"{base}.role", "missing role")
                elif pos["role"] not in ALLOWED_ROLES:
                    err(f"{base}.role", f"role '{pos['role']}' not allowed")
                for j, t in enumerate(pos.get("techniques", [])):
                    if not re.match(r"^IIM-T\d{3}$", str(t)):
                        err(f"{base}.techniques[{j}]", f"invalid technique id: {t}")
                    elif self.technique_ids and t not in self.technique_ids:
                        warn(f"{base}.techniques[{j}]", f"technique {t} not in catalog")

        ms = pattern.get("match_semantics")
        if ms and ms not in ALLOWED_MATCH_SEMANTICS:
            err("$.match_semantics", f"must be one of {sorted(ALLOWED_MATCH_SEMANTICS)}")

        relations = pattern.get("relations", [])
        shape_len = len(shape)
        for i, rel in enumerate(relations):
            base = f"$.relations[{i}]"
            fp = rel.get("from_position")
            tp = rel.get("to_position")
            if fp is None or tp is None:
                err(base, "relation must have from_position and to_position")
                continue
            if not (0 <= fp < shape_len):
                err(f"{base}.from_position", f"out of range [0, {shape_len-1}]")
            if not (0 <= tp < shape_len):
                err(f"{base}.to_position", f"out of range [0, {shape_len-1}]")

        return {"valid": not errors, "errors": errors, "warnings": warnings}


# this is our STIX 2.1 exporter
def _stix_uuid(namespace: str, key: str) -> str:
    """Deterministic UUID for round-trippable exports."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"iim:{namespace}:{key}"))


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_pattern_for_entity(ent: dict) -> str:
    """Produce a STIX pattern string for a given IIM entity."""
    etype = ent.get("type", "")
    val = ent.get("value", "").replace("'", "\\'")
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


def chain_to_stix(chain: dict, catalog: dict) -> dict:
    """Convert an IIM chain to a STIX 2.1 Bundle."""
    now = _now_utc_iso()
    cid = chain.get("chain_id", "unnamed")
    objects: list[dict] = []
    ref: dict[str, str] = {}

    # Identity (publisher)
    ident_id = "identity--" + _stix_uuid("identity", "iim-workbench")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": ident_id,
        "created": now,
        "modified": now,
        "name": "IIM Workbench",
        "identity_class": "system",
    })

    # Entity indicators
    for ent in chain.get("entities", []):
        eid = ent["id"]
        ind_id = "indicator--" + _stix_uuid("indicator", f"{cid}:{eid}")
        ref[f"ind:{eid}"] = ind_id
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "created_by_ref": ident_id,
            "pattern": _stix_pattern_for_entity(ent),
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "x_iim_entity_type": ent["type"],
            "x_iim_entity_id": eid,
        })

    # Infrastructure objects per role position
    for i, pos in enumerate(chain.get("chain", [])):
        eid = pos["entity_id"]
        role = pos.get("role", "unknown")
        infra_id = "infrastructure--" + _stix_uuid("infrastructure", f"{cid}:pos{i}:{eid}")
        ref[f"infra:{i}"] = infra_id
        ent = next((e for e in chain.get("entities", []) if e["id"] == eid), {})
        name = f"{role.capitalize()} · {ent.get('value', eid)}"
        objects.append({
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": now,
            "modified": now,
            "created_by_ref": ident_id,
            "name": name,
            "infrastructure_types": _stix_infrastructure_type(role),
            "x_iim_role": role,
            "x_iim_chain_id": cid,
            "x_iim_position": i,
            "x_iim_techniques": pos.get("techniques", []),
        })
        # Link indicator -> infrastructure
        if f"ind:{eid}" in ref:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--" + _stix_uuid("rel", f"{cid}:indicates:{eid}:{i}"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ref[f"ind:{eid}"],
                "target_ref": infra_id,
            })

    # Technique attack-patterns (namespaced)
    seen_techs: set[str] = set()
    tech_map = {t["id"]: t for t in catalog.get("techniques", [])}
    for pos in chain.get("chain", []):
        for tid in pos.get("techniques", []):
            if tid in seen_techs: continue
            seen_techs.add(tid)
            ap_id = "attack-pattern--" + _stix_uuid("technique", tid)
            ref[f"tech:{tid}"] = ap_id
            info = tech_map.get(tid, {})
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "created_by_ref": ident_id,
                "name": info.get("name", tid),
                "description": info.get("description", ""),
                "external_references": [{
                    "source_name": "iim",
                    "external_id": tid,
                    "url": f"https://iim.malwarebox.eu/techniques/{tid}",
                }],
                "x_iim_category": info.get("category", ""),
            })

    # "uses" relationships: infrastructure -> technique
    for i, pos in enumerate(chain.get("chain", [])):
        for tid in pos.get("techniques", []):
            if f"tech:{tid}" not in ref: continue
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--" + _stix_uuid("rel", f"{cid}:uses:{i}:{tid}"),
                "created": now,
                "modified": now,
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
        if fp is None or tp is None: continue
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--" + _stix_uuid("rel", f"{cid}:flow:{fp}:{tp}:{rel.get('type')}"),
            "created": now,
            "modified": now,
            "relationship_type": "related-to",
            "source_ref": ref[f"infra:{fp}"],
            "target_ref": ref[f"infra:{tp}"],
            "x_iim_relation_type": rel.get("type"),
            "x_iim_sequence_order": rel.get("sequence_order"),
        })

    # Grouping wraps the whole chain
    group_id = "grouping--" + _stix_uuid("grouping", cid)
    objects.insert(1, {
        "type": "grouping",
        "spec_version": "2.1",
        "id": group_id,
        "created": now,
        "modified": now,
        "created_by_ref": ident_id,
        "name": f"IIM Chain · {cid}",
        "context": "iim-chain",
        "object_refs": [o["id"] for o in objects if o["id"] != ident_id],
        "x_iim_chain_id": cid,
        "x_iim_version": chain.get("iim_version", "1.1"),
    })

    return {
        "type": "bundle",
        "id": "bundle--" + _stix_uuid("bundle", cid),
        "objects": objects,
    }



# Pattern extraction (chain -> pattern)


def chain_to_pattern(chain: dict, pattern_id: str = "MB-F-0000", name: str = "Derived Pattern",
                     match_semantics: str = "structural") -> dict:
    position_by_entity = {p["entity_id"]: i for i, p in enumerate(chain.get("chain", []))}
    shape = [{
        "role": p.get("role"),
        "techniques": p.get("techniques", []),
    } for p in chain.get("chain", [])]
    relations = []
    for rel in chain.get("relations", []):
        fp = position_by_entity.get(rel.get("from"))
        tp = position_by_entity.get(rel.get("to"))
        if fp is None or tp is None: continue
        relations.append({
            "from_position": fp,
            "to_position": tp,
            "type": rel.get("type"),
        })
    return {
        "pattern_id": pattern_id,
        "name": name,
        "iim_version": chain.get("iim_version", "1.1"),
        "shape": shape,
        "relations": relations,
        "match_semantics": match_semantics,
        "derived_from": [chain.get("chain_id")],
    }



# Flask app


def create_app(catalog_path: str | None = None) -> Flask:
    app = Flask(__name__)
    catalog = load_catalog(catalog_path)
    validator = Validator(catalog)

    @app.route("/")
    def index():
        return render_template_string(
            INDEX_HTML,
            catalog_version=catalog.get("catalog_version", "?"),
            spec_version=catalog.get("spec_version", "?"),
            technique_count=len(catalog.get("techniques", [])),
            version=VERSION,
        )

    @app.route("/api/catalog")
    def api_catalog():
        return jsonify(catalog)

    @app.route("/api/techniques")
    def api_techniques():
        q = (request.args.get("q", "") or "").lower().strip()
        cat = request.args.get("category", "").strip()
        techs = catalog.get("techniques", [])
        if q:
            techs = [t for t in techs if
                     q in t["id"].lower() or
                     q in t["name"].lower() or
                     q in t.get("short", "").lower() or
                     q in t.get("description", "").lower()]
        if cat:
            techs = [t for t in techs if t.get("category") == cat]
        return jsonify({"techniques": techs, "count": len(techs)})

    @app.route("/api/techniques/<tid>")
    def api_technique_detail(tid):
        for t in catalog.get("techniques", []):
            if t["id"].lower() == tid.lower():
                return jsonify(t)
        return jsonify({"error": "not found"}), 404

    @app.route("/api/validate/chain", methods=["POST"])
    def api_validate_chain():
        try:
            data = request.get_json(force=True)
        except Exception as e:
            return jsonify({"valid": False, "errors": [{"path": "$", "message": f"invalid JSON: {e}"}], "warnings": []}), 400
        return jsonify(validator.validate_chain(data))

    @app.route("/api/validate/pattern", methods=["POST"])
    def api_validate_pattern():
        try:
            data = request.get_json(force=True)
        except Exception as e:
            return jsonify({"valid": False, "errors": [{"path": "$", "message": f"invalid JSON: {e}"}], "warnings": []}), 400
        return jsonify(validator.validate_pattern(data))

    @app.route("/api/export/stix", methods=["POST"])
    def api_export_stix():
        try:
            chain = request.get_json(force=True)
        except Exception as e:
            return jsonify({"error": f"invalid JSON: {e}"}), 400
        result = validator.validate_chain(chain)
        if not result["valid"]:
            return jsonify({"error": "chain is invalid", "validation": result}), 400
        bundle = (_lib_iim_chain_to_stix(chain, catalog) if _lib_iim_chain_to_stix else chain_to_stix(chain, catalog))
        return jsonify(bundle)

    @app.route("/api/import/stix", methods=["POST"])
    def api_import_stix():
        if not HAS_STIX_IMPORT:
            return jsonify({
                "error": "STIX import requires iim_stix.py in the same directory"
            }), 501
        try:
            payload = request.get_json(force=True)
        except Exception as e:
            return jsonify({"error": f"invalid JSON: {e}"}), 400
        bundle = payload.get("bundle", payload)
        chain_id_override = payload.get("chain_id") if isinstance(payload, dict) else None
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            return jsonify({"error": "input is not a STIX bundle"}), 400
        try:
            chain = _stix_to_iim_chain(bundle, chain_id=chain_id_override)
            report = _import_report(bundle, chain)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": f"conversion failed: {e}"}), 500
        # Validate the produced chain
        validation = validator.validate_chain(chain)
        return jsonify({
            "chain":      chain,
            "report":     report,
            "validation": validation,
        })

    @app.route("/api/export/pattern", methods=["POST"])
    def api_export_pattern():
        try:
            payload = request.get_json(force=True)
        except Exception as e:
            return jsonify({"error": f"invalid JSON: {e}"}), 400
        chain = payload.get("chain", payload)
        pattern_id = payload.get("pattern_id", "MB-F-0000")
        name = payload.get("name", "Derived Pattern")
        semantics = payload.get("match_semantics", "structural")
        result = validator.validate_chain(chain)
        if not result["valid"]:
            return jsonify({"error": "chain is invalid", "validation": result}), 400
        pattern = chain_to_pattern(chain, pattern_id, name, semantics)
        return jsonify(pattern)

    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "version": VERSION,
            "catalog_version": catalog.get("catalog_version"),
            "technique_count": len(catalog.get("techniques", [])),
        })

    return app



# HTML frontend (embedded)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IIM Workbench</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  :root {
    --abyss: #030812; --deep: #061019; --trench: #0a1826; --current: #0f2235;
    --bio: #6de4ff; --plankton: #3ad0a8; --amber: #ffb454; --coral: #ff7a5c;
    --kraken-blue: #2d5fff; --bone: #e8ecf2; --bone-dim: #9aa8bd; --bone-darker: #5a6a82;
    --ink: rgba(109, 228, 255, 0.14);
    --role-entry: #8ec7ff; --role-redirector: #b39dff;
    --role-staging: #3ad0a8; --role-payload: #ff7a5c; --role-c2: #ffb454;

    /* System font stacks - zero external loads */
    --font-mono: ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
    --font-serif: ui-serif, Georgia, 'Times New Roman', 'Nimbus Roman', serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { background: var(--abyss); color: var(--bone); font-family: var(--font-mono); font-size: 13px; line-height: 1.6; -webkit-font-smoothing: antialiased; min-height: 100vh; }
  body {
    background:
      radial-gradient(ellipse 90% 50% at 50% -10%, rgba(15, 34, 53, 0.8) 0%, transparent 55%),
      radial-gradient(ellipse 60% 40% at 90% 100%, rgba(58, 208, 168, 0.06) 0%, transparent 55%),
      var(--abyss);
  }
  body::before {
    content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2'/><feColorMatrix values='0 0 0 0 0.4  0 0 0 0 0.9  0 0 0 0 1  0 0 0 0.03 0'/></filter><rect width='100%25' height='100%25' filter='url(%23n)'/></svg>");
    mix-blend-mode: screen; opacity: 0.5;
  }

  /* Topbar */
  .topbar {
    position: sticky; top: 0; z-index: 50;
    background: rgba(3, 8, 18, 0.85); backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--ink);
    padding: 14px 28px; display: flex; justify-content: space-between; align-items: center;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-logo {
    width: 32px; height: 32px;
    flex-shrink: 0;
  }
  .brand-text { font-family: var(--font-serif); font-size: 17px; font-weight: 400; }
  .brand-text em { font-style: italic; color: var(--plankton); font-weight: 500; }
  .brand-tag { font-size: 9px; letter-spacing: 0.25em; color: var(--bone-darker); text-transform: uppercase; margin-top: 2px; }
  .status-pills { display: flex; gap: 10px; align-items: center; }
  .pill {
    padding: 5px 12px; font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase;
    color: var(--bone-dim); border: 1px solid var(--ink); border-radius: 2px;
  }
  .pill.live { color: var(--plankton); border-color: rgba(58, 208, 168, 0.3); }
  .pill.live::before { content: '●'; margin-right: 6px; animation: blink 2s infinite; }
  @keyframes blink { 50% { opacity: 0.4; } }

  /* Tabs */
  .tabs {
    display: flex; gap: 0; padding: 0 28px; border-bottom: 1px solid var(--ink);
    background: rgba(6, 16, 25, 0.5); position: relative; z-index: 1;
  }
  .tab {
    padding: 14px 22px; font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase;
    color: white; cursor: pointer; border-bottom: 2px solid transparent;
    transition: all 0.2s; user-select: none;
  }
  .tab:hover { color: var(--bone-dim); }
  .tab.active { color: var(--plankton); border-bottom-color: var(--plankton); }
  .tab .count { color: var(--bone-darker); margin-left: 8px; font-size: 10px; }

  /* Main */
  main { padding: 32px 28px; position: relative; z-index: 1; max-width: 1600px; margin: 0 auto; }
  .panel { display: none; }
  .panel.active { display: block; }
  .panel h1 {
    font-family: var(--font-serif); font-weight: 300; font-size: 32px; letter-spacing: -0.015em;
    margin-bottom: 8px;
  }
  .panel h1 em { font-style: italic; color: var(--plankton); }
  .panel .lead { color: var(--bone-dim); font-size: 13px; max-width: 720px; margin-bottom: 28px; line-height: 1.75; }

  /* ====================================================================
     BUILDER PANEL
     ==================================================================== */
  .builder-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 1100px) { .builder-grid { grid-template-columns: 1fr; } }

  .card {
    background: var(--deep); border: 1px solid var(--ink); border-radius: 4px;
    padding: 20px 22px;
  }
  .card-head {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--ink);
  }
  .card-head h3 {
    font-family: var(--font-serif); font-weight: 500; font-size: 16px;
    display: flex; align-items: center; gap: 10px;
  }
  .card-head h3 .badge {
    font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.2em;
    padding: 2px 8px; border: 1px solid var(--ink); color: white; text-transform: uppercase;
  }
  .card-actions { display: flex; gap: 6px; }

  /* Form fields */
  .field { margin-bottom: 12px; }
  .field label {
    display: block; font-size: 9px; letter-spacing: 0.25em;
    text-transform: uppercase; color: white; margin-bottom: 6px;
  }
  input[type="text"], select, textarea {
    width: 100%; background: var(--abyss); border: 1px solid var(--ink);
    color: var(--bone); padding: 9px 12px; font-family: inherit; font-size: 12px;
    border-radius: 2px; transition: border-color 0.2s;
  }
  input[type="text"]:focus, select:focus, textarea:focus {
    outline: none; border-color: var(--plankton);
    box-shadow: 0 0 0 2px rgba(58, 208, 168, 0.1);
  }
  textarea { font-family: var(--font-mono); font-size: 11px; line-height: 1.55; resize: vertical; min-height: 200px; }

  .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .field-row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }

  /* Buttons */
  .btn {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 7px 14px; background: transparent;
    border: 1px solid var(--ink); color: var(--bone-dim);
    font-family: inherit; font-size: 10px; letter-spacing: 0.2em;
    text-transform: uppercase; cursor: pointer; border-radius: 2px;
    transition: all 0.2s;
  }
  .btn:hover { border-color: var(--plankton); color: var(--plankton); }
  .btn.primary { color: var(--plankton); border-color: var(--plankton); background: rgba(58, 208, 168, 0.05); }
  .btn.primary:hover { background: rgba(58, 208, 168, 0.12); }
  .btn.danger { color: var(--coral); border-color: rgba(255, 122, 92, 0.3); }
  .btn.danger:hover { background: rgba(255, 122, 92, 0.08); }
  .btn.small { padding: 4px 10px; font-size: 9px; }

  /* Entity list */
  .entity-list { display: flex; flex-direction: column; gap: 8px; }
  .entity-row {
    display: grid; grid-template-columns: 70px 100px 1fr 28px;
    gap: 8px; align-items: center; padding: 6px; background: var(--trench);
    border: 1px solid var(--ink); border-radius: 2px;
  }
  .entity-row input, .entity-row select {
    padding: 6px 8px; font-size: 11px;
  }
  .entity-row .id-field { color: var(--plankton); font-weight: 500; }

  /* Chain list */
  .chain-list { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
  .chain-pos {
    display: grid; grid-template-columns: 30px 1fr 120px 1fr 28px;
    gap: 8px; align-items: center; padding: 8px 10px;
    background: var(--trench); border: 1px solid var(--ink);
    border-left: 3px solid var(--role-color, var(--ink)); border-radius: 2px;
  }
  .chain-pos[data-role="entry"] { --role-color: var(--role-entry); }
  .chain-pos[data-role="redirector"] { --role-color: var(--role-redirector); }
  .chain-pos[data-role="staging"] { --role-color: var(--role-staging); }
  .chain-pos[data-role="payload"] { --role-color: var(--role-payload); }
  .chain-pos[data-role="c2"] { --role-color: var(--role-c2); }
  .chain-pos .pos-idx {
    font-size: 10px; color: var(--bone-darker); text-align: center;
    letter-spacing: 0.1em;
  }
  .chain-pos .tech-chips {
    display: flex; flex-wrap: wrap; gap: 4px;
    min-height: 26px; align-items: center;
    padding: 2px 6px; background: var(--abyss);
    border: 1px solid var(--ink); cursor: text; border-radius: 2px;
  }
  .chip {
    font-size: 9px; padding: 2px 6px; background: rgba(58, 208, 168, 0.1);
    border: 1px solid rgba(58, 208, 168, 0.3); color: var(--plankton);
    letter-spacing: 0.05em; display: inline-flex; align-items: center; gap: 4px;
  }
  .chip .chip-x {
    cursor: pointer; color: var(--bone-darker);
  }
  .chip .chip-x:hover { color: var(--coral); }

  /* Relation list */
  .rel-list { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
  .rel-row {
    display: grid; grid-template-columns: 1fr 120px 1fr 70px 28px;
    gap: 8px; align-items: center; padding: 6px;
    background: var(--trench); border: 1px solid var(--ink); border-radius: 2px;
  }
  .rel-row select { padding: 6px 8px; font-size: 11px; }
  .rel-row input { padding: 6px 8px; font-size: 11px; text-align: center; }
  .rel-arrow {
    color: var(--bone-darker); text-align: center; font-size: 14px;
  }

  .remove-btn {
    background: transparent; border: none; color: var(--bone-darker);
    cursor: pointer; font-size: 14px; padding: 4px;
    transition: color 0.2s;
  }
  .remove-btn:hover { color: var(--coral); }

  /* JSON output */
  .json-output {
    background: var(--abyss); border: 1px solid var(--ink);
    padding: 14px; font-family: var(--font-mono);
    font-size: 11px; line-height: 1.6; white-space: pre-wrap; word-break: break-all;
    max-height: 520px; overflow: auto; color: var(--bone-dim);
    border-radius: 2px;
  }
  .json-output .key { color: var(--bio); }
  .json-output .str { color: var(--plankton); }
  .json-output .num { color: var(--amber); }
  .json-output .bool { color: var(--coral); }

  /* Validation results */
  .validation {
    margin-top: 14px; padding: 12px 14px;
    border-left: 3px solid var(--plankton);
    background: rgba(58, 208, 168, 0.04);
    font-size: 11px;
  }
  .validation.invalid {
    border-left-color: var(--coral);
    background: rgba(255, 122, 92, 0.04);
  }
  .validation h4 {
    font-family: var(--font-serif); font-weight: 500; font-size: 13px;
    margin-bottom: 8px;
  }
  .validation.valid h4 { color: var(--plankton); }
  .validation.invalid h4 { color: var(--coral); }
  .validation ul { list-style: none; padding: 0; }
  .validation li { padding: 3px 0; font-size: 10px; color: var(--bone-dim); }
  .validation li .path { color: var(--amber); font-family: inherit; }
  .validation li.warn .path { color: var(--amber); }
  .validation li.err .path { color: var(--coral); }

  /* ====================================================================
     TECHNIQUES PANEL
     ==================================================================== */
  .tech-controls {
    display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap;
  }
  .tech-controls input { flex: 1; max-width: 400px; }
  .tech-controls select { max-width: 200px; }

  .tech-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
  }
  .tech-card {
    background: var(--deep); border: 1px solid var(--ink);
    padding: 16px 18px; transition: all 0.2s; cursor: pointer;
    border-radius: 3px; position: relative;
  }
  .tech-card:hover {
    border-color: var(--plankton);
    transform: translateY(-1px);
  }
  .tech-card .t-id {
    font-size: 10px; letter-spacing: 0.15em; color: var(--plankton); font-weight: 500;
  }
  .tech-card .t-name {
    font-family: var(--font-serif); font-weight: 400; font-size: 17px;
    color: var(--bone); margin: 6px 0 8px; line-height: 1.25;
  }
  .tech-card .t-cat {
    display: inline-block; font-size: 9px; letter-spacing: 0.2em;
    text-transform: uppercase; color: var(--bone-darker);
    padding: 2px 8px; border: 1px solid var(--ink);
    margin-bottom: 10px;
  }
  .tech-card .t-short {
    font-size: 11px; color: var(--bone-dim); line-height: 1.6;
  }

  /* Technique detail modal */
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(3, 8, 18, 0.85);
    backdrop-filter: blur(6px); z-index: 100;
    display: none; align-items: center; justify-content: center; padding: 40px;
  }
  .modal-backdrop.active { display: flex; }
  .modal {
    background: var(--deep); border: 1px solid var(--ink);
    max-width: 780px; max-height: 86vh; overflow-y: auto;
    padding: 32px 36px; border-radius: 4px; position: relative;
  }
  .modal .close {
    position: absolute; top: 16px; right: 18px;
    background: transparent; border: none; color: var(--bone-darker);
    font-size: 20px; cursor: pointer;
  }
  .modal .close:hover { color: var(--coral); }
  .modal h2 {
    font-family: var(--font-serif); font-weight: 300; font-size: 28px;
    margin-bottom: 6px; letter-spacing: -0.01em;
  }
  .modal .m-id {
    font-size: 11px; color: var(--plankton); letter-spacing: 0.2em; margin-bottom: 14px;
  }
  .modal h4 {
    font-size: 10px; letter-spacing: 0.25em; text-transform: uppercase;
    color: var(--bone-darker); margin: 20px 0 8px; padding-bottom: 6px;
    border-bottom: 1px solid var(--ink);
  }
  .modal p, .modal li {
    font-size: 12px; color: var(--bone-dim); line-height: 1.7;
    margin-bottom: 8px;
  }
  .modal ul { padding-left: 20px; }
  .modal .why {
    padding: 10px 14px; background: rgba(58, 208, 168, 0.04);
    border-left: 2px solid var(--plankton); margin: 10px 0; font-size: 11px;
  }
  .modal .example {
    padding: 10px 14px; background: rgba(109, 228, 255, 0.04);
    border-left: 2px solid var(--bio); margin: 10px 0;
    font-family: var(--font-mono); font-size: 11px;
    color: var(--bone); line-height: 1.6;
  }

  /* ====================================================================
     VALIDATOR PANEL
     ==================================================================== */
  .validator-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 1100px) { .validator-grid { grid-template-columns: 1fr; } }
  .validator-input textarea { min-height: 440px; }

  /* ====================================================================
     TOAST
     ==================================================================== */
  .toast {
    position: fixed; bottom: 24px; right: 24px; z-index: 200;
    padding: 12px 18px; background: var(--deep);
    border: 1px solid var(--plankton); border-left: 3px solid var(--plankton);
    font-size: 11px; color: var(--bone); letter-spacing: 0.05em;
    transform: translateX(400px); transition: transform 0.3s;
    border-radius: 2px;
  }
  .toast.show { transform: translateX(0); }
  .toast.error { border-color: var(--coral); border-left-color: var(--coral); }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: var(--abyss); }
  ::-webkit-scrollbar-thumb { background: var(--current); border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--bio); }

  /* Help snippet */
  .help-snippet {
    margin-top: 24px; padding: 14px 18px;
    background: rgba(109, 228, 255, 0.03);
    border-left: 2px solid var(--bio);
    font-size: 11px; color: var(--bone-dim); line-height: 1.7;
  }
  .help-snippet b { color: var(--bio); font-weight: 500; }
  .help-snippet code {
    background: var(--abyss); padding: 1px 6px;
    border: 1px solid var(--ink); font-size: 10px; color: var(--plankton);
  }

  /* ====================================================================
     VISUALIZE PANEL
     ==================================================================== */
  .viz-layout {
    display: grid; grid-template-columns: 340px 1fr; gap: 16px;
    height: calc(100vh - 260px); min-height: 600px;
  }
  @media (max-width: 1100px) { .viz-layout { grid-template-columns: 1fr; height: auto; } }

  .viz-sidebar {
    display: flex; flex-direction: column; gap: 14px;
    overflow-y: auto; max-height: 100%;
  }
  .viz-sidebar .card { padding: 16px 18px; }
  .viz-sidebar textarea { min-height: 180px; font-size: 10px; }

  .viz-stage {
    background: var(--deep); border: 1px solid var(--ink);
    border-radius: 4px; position: relative; overflow: hidden;
    display: flex; flex-direction: column;
  }

  .viz-toolbar {
    padding: 10px 14px; border-bottom: 1px solid var(--ink);
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    background: rgba(3, 8, 18, 0.3);
  }
  .viz-mode-group {
    display: inline-flex; border: 1px solid var(--ink); border-radius: 2px;
  }
  .viz-mode-btn {
    padding: 6px 14px; background: transparent; border: none;
    color: var(--bone-darker); font-family: inherit; font-size: 10px;
    letter-spacing: 0.2em; text-transform: uppercase; cursor: pointer;
    border-right: 1px solid var(--ink); transition: all 0.2s;
  }
  .viz-mode-btn:last-child { border-right: none; }
  .viz-mode-btn.active {
    background: rgba(58, 208, 168, 0.1); color: var(--plankton);
  }
  .viz-mode-btn:hover:not(.active) { color: var(--bone-dim); }

  .viz-info {
    margin-left: auto; font-size: 10px; color: var(--bone-darker);
    letter-spacing: 0.1em; display: flex; gap: 14px; align-items: center;
  }
  .viz-info .kv { display: flex; gap: 6px; }
  .viz-info .kv .k { color: var(--bone-darker); }
  .viz-info .kv .v { color: var(--bone); }

  .viz-canvas-wrap {
    flex: 1; position: relative; overflow: hidden;
    background:
      radial-gradient(ellipse 80% 60% at 50% 50%, rgba(15, 34, 53, 0.4) 0%, transparent 70%),
      var(--abyss);
  }
  .viz-canvas-wrap::before {
    content: ''; position: absolute; inset: 0;
    background-image:
      radial-gradient(circle at 1px 1px, rgba(109, 228, 255, 0.06) 1px, transparent 0);
    background-size: 24px 24px;
    pointer-events: none;
  }

  .viz-svg { width: 100%; height: 100%; display: block; cursor: grab; }
  .viz-svg:active { cursor: grabbing; }

  /* Role-colored styling for SVG elements */
  .viz-svg .node-entry      { fill: #101c2c; stroke: var(--role-entry); }
  .viz-svg .node-redirector { fill: #141a30; stroke: var(--role-redirector); }
  .viz-svg .node-staging    { fill: #0c1e1a; stroke: var(--role-staging); }
  .viz-svg .node-payload    { fill: #241210; stroke: var(--role-payload); }
  .viz-svg .node-c2         { fill: #2a1e0d; stroke: var(--role-c2); }

  .viz-svg .node-body { stroke-width: 1.5; rx: 4; transition: filter 0.2s; }
  .viz-svg .node-body:hover { filter: brightness(1.3) drop-shadow(0 0 8px currentColor); }

  .viz-svg text { font-family: var(--font-mono); fill: var(--bone); }
  .viz-svg .node-role-label {
    font-size: 9px; letter-spacing: 0.15em; text-transform: uppercase;
  }
  .viz-svg .node-role-label.entry      { fill: var(--role-entry); }
  .viz-svg .node-role-label.redirector { fill: var(--role-redirector); }
  .viz-svg .node-role-label.staging    { fill: var(--role-staging); }
  .viz-svg .node-role-label.payload    { fill: var(--role-payload); }
  .viz-svg .node-role-label.c2         { fill: var(--role-c2); }

  .viz-svg .node-entity-label { font-size: 11px; fill: var(--bone); font-weight: 500; }
  .viz-svg .node-entity-type { font-size: 9px; fill: var(--bone-darker); letter-spacing: 0.1em; }
  .viz-svg .node-pos-idx {
    font-size: 9px; fill: var(--bone-darker); letter-spacing: 0.15em;
    font-family: var(--font-serif); font-weight: 500;
  }
  .viz-svg .tech-chip-bg { fill: rgba(58, 208, 168, 0.12); stroke: rgba(58, 208, 168, 0.4); stroke-width: 0.5; rx: 2; }
  .viz-svg .tech-chip-label { font-size: 8px; fill: var(--plankton); letter-spacing: 0.05em; }

  .viz-svg .edge {
    fill: none; stroke: var(--bone-darker); stroke-width: 1.2;
    opacity: 0.6; transition: opacity 0.2s, stroke-width 0.2s;
  }
  .viz-svg .edge:hover { opacity: 1; stroke-width: 2; stroke: var(--bio); }
  .viz-svg .edge-label {
    font-size: 9px; fill: var(--bone-darker); letter-spacing: 0.05em;
  }
  .viz-svg .arrow-head { fill: var(--bone-darker); }

  .viz-svg .seq-badge {
    fill: var(--abyss); stroke: var(--plankton); stroke-width: 1; rx: 10;
  }
  .viz-svg .seq-badge-label {
    font-size: 9px; fill: var(--plankton); letter-spacing: 0.1em;
    font-weight: 500; font-family: var(--font-serif);
  }

  .viz-legend {
    position: absolute; bottom: 14px; left: 14px;
    background: rgba(6, 16, 25, 0.85); backdrop-filter: blur(6px);
    border: 1px solid var(--ink); padding: 10px 12px; border-radius: 3px;
    display: flex; flex-direction: column; gap: 5px; z-index: 5;
  }
  .viz-legend .legend-title {
    font-size: 9px; letter-spacing: 0.25em; color: var(--bone-darker);
    text-transform: uppercase; margin-bottom: 4px; padding-bottom: 4px;
    border-bottom: 1px solid var(--ink);
  }
  .viz-legend .legend-row {
    display: flex; align-items: center; gap: 8px;
    font-size: 10px; color: var(--bone-dim);
  }
  .viz-legend .legend-swatch {
    width: 10px; height: 10px; border-radius: 2px;
    border: 1px solid currentColor;
  }
  .legend-entry      { color: var(--role-entry); }
  .legend-redirector { color: var(--role-redirector); }
  .legend-staging    { color: var(--role-staging); }
  .legend-payload    { color: var(--role-payload); }
  .legend-c2         { color: var(--role-c2); }

  .viz-empty {
    position: absolute; inset: 0; display: flex;
    flex-direction: column; align-items: center; justify-content: center;
    color: var(--bone-darker); text-align: center; padding: 40px;
  }
  .viz-empty h4 {
    font-family: var(--font-serif); font-weight: 300;
    font-size: 22px; color: var(--bone-dim); margin-bottom: 10px;
  }
  .viz-empty p { font-size: 11px; max-width: 360px; line-height: 1.7; }

  /* Example chain library */
  .example-list { display: flex; flex-direction: column; gap: 6px; }
  .example-item {
    padding: 10px 12px; background: var(--trench); border: 1px solid var(--ink);
    border-radius: 2px; cursor: pointer; transition: all 0.2s;
  }
  .example-item:hover {
    border-color: var(--plankton);
    background: rgba(58, 208, 168, 0.04);
  }
  .example-item .ex-name {
    font-family: var(--font-serif); font-size: 13px;
    color: var(--bone); margin-bottom: 3px;
  }
  .example-item .ex-meta {
    font-size: 9px; color: var(--bone-darker);
    letter-spacing: 0.1em; text-transform: uppercase;
    display: flex; gap: 10px;
  }
  .example-item .ex-meta .dot-sep { color: var(--ink); }

  /* Node detail popover */
  .viz-popover {
    position: absolute; background: var(--deep); border: 1px solid var(--plankton);
    border-left: 3px solid var(--plankton); padding: 14px 16px; z-index: 20;
    max-width: 320px; border-radius: 3px;
    box-shadow: 0 8px 28px rgba(0,0,0,0.5);
    display: none; pointer-events: auto;
  }
  .viz-popover.show { display: block; }
  .viz-popover h5 {
    font-family: var(--font-serif); font-weight: 500; font-size: 14px;
    margin-bottom: 8px;
  }
  .viz-popover .pop-kv {
    display: grid; grid-template-columns: 70px 1fr; gap: 6px;
    font-size: 10px; padding: 3px 0; border-bottom: 1px solid var(--ink);
  }
  .viz-popover .pop-kv:last-of-type { border-bottom: none; }
  .viz-popover .pop-kv .k { color: var(--bone-darker); letter-spacing: 0.1em; text-transform: uppercase; }
  .viz-popover .pop-kv .v { color: var(--bone); word-break: break-all; }
  .viz-popover .pop-close {
    position: absolute; top: 8px; right: 10px;
    background: transparent; border: none; color: var(--bone-darker);
    cursor: pointer; font-size: 14px;
  }
  .viz-popover .pop-close:hover { color: var(--coral); }

  /* ====================================================================
     MOBILE RESPONSIVE - tablet & phone breakpoints
     ==================================================================== */

  /* Tablet - 900px and below */
  @media (max-width: 900px) {
    .topbar {
      padding: 10px 16px;
      flex-wrap: wrap;
      gap: 10px;
    }
    .brand { gap: 10px; }
    .brand-logo {
      width: 28px !important;
      height: 28px !important;
    }
    .brand-text { font-size: 15px; }
    .brand-tag { font-size: 8px; letter-spacing: 0.2em; }
    .status-pills {
      width: 100%;
      justify-content: flex-start;
      flex-wrap: wrap;
      gap: 6px;
    }
    .pill { font-size: 9px; padding: 4px 10px; }

    .tabs {
      padding: 0 16px;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: none;
    }
    .tabs::-webkit-scrollbar { display: none; }
    .tab {
      padding: 12px 14px;
      font-size: 10px;
      letter-spacing: 0.15em;
      white-space: nowrap;
      flex-shrink: 0;
    }

    main { padding: 20px 16px; }
    .panel h1 { font-size: 26px; }
    .panel .lead { font-size: 12px; }

    .builder-grid,
    .validator-grid,
    .viz-layout {
      grid-template-columns: 1fr !important;
      gap: 14px;
    }

    .viz-layout { height: auto !important; }
    .viz-stage { min-height: 480px; }
  }

  /* Phone - 640px and below */
  @media (max-width: 640px) {
    html, body { font-size: 13px; }

    .topbar {
      padding: 8px 12px;
      gap: 8px;
    }
    .brand-tag { display: none; }

    main { padding: 16px 12px; }

    .panel h1 { font-size: 22px; letter-spacing: -0.01em; }
    .panel .lead { font-size: 12px; line-height: 1.65; margin-bottom: 20px; }

    .card {
      padding: 14px 16px;
    }
    .card-head {
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
      padding-bottom: 10px;
    }
    .card-head h3 { font-size: 14px; }
    .card-head .badge { font-size: 8px; padding: 2px 6px; }
    .card-actions { width: 100%; justify-content: flex-start; }

    /* Entity rows: stack into a 3-row layout */
    .entity-row {
      grid-template-columns: 1fr 1fr 32px;
      grid-template-areas:
        "id type remove"
        "value value value";
      gap: 6px;
      padding: 8px;
    }
    .entity-row > *:nth-child(1) { grid-area: id; }
    .entity-row > *:nth-child(2) { grid-area: type; }
    .entity-row > *:nth-child(3) { grid-area: value; }
    .entity-row > *:nth-child(4) { grid-area: remove; }

    /* Chain positions: stack */
    .chain-pos {
      grid-template-columns: 32px 1fr 32px;
      grid-template-areas:
        "idx entity remove"
        "role role role"
        "techs techs techs";
      gap: 6px;
      padding: 10px;
    }
    .chain-pos > *:nth-child(1) { grid-area: idx; }
    .chain-pos > *:nth-child(2) { grid-area: entity; }
    .chain-pos > *:nth-child(3) { grid-area: role; }
    .chain-pos > *:nth-child(4) { grid-area: techs; }
    .chain-pos > *:nth-child(5) { grid-area: remove; }

    /* Relations: stack from/type/to */
    .rel-row {
      grid-template-columns: 1fr 1fr 40px;
      grid-template-areas:
        "from to remove"
        "type type type"
        "seq seq seq";
      gap: 6px;
      padding: 8px;
    }
    .rel-row > *:nth-child(1) { grid-area: from; }
    .rel-row > *:nth-child(2) { grid-area: type; }
    .rel-row > *:nth-child(3) { grid-area: to; }
    .rel-row > *:nth-child(4) { grid-area: seq; }
    .rel-row > *:nth-child(5) { grid-area: remove; }

    .field-row, .field-row-3 {
      grid-template-columns: 1fr;
    }

    textarea { min-height: 160px; font-size: 11px; }

    .json-output {
      font-size: 10px;
      padding: 10px;
      max-height: 360px;
    }

    /* Buttons - bigger tap area on phone */
    .btn {
      padding: 8px 12px;
      font-size: 10px;
    }
    .btn.small {
      padding: 5px 10px;
      font-size: 9px;
    }

    /* Technique catalog - 1 column on phone */
    .tech-grid {
      grid-template-columns: 1fr;
      gap: 10px;
    }
    .tech-card { padding: 14px 16px; }
    .tech-card .t-name { font-size: 15px; }

    .tech-controls {
      flex-direction: column;
      gap: 8px;
    }
    .tech-controls input, .tech-controls select {
      max-width: 100%;
      width: 100%;
    }

    /* Modal */
    .modal-backdrop { padding: 12px; }
    .modal {
      padding: 22px 20px;
      max-height: 90vh;
    }
    .modal h2 { font-size: 22px; }

    /* Visualizer */
    .viz-toolbar {
      padding: 8px 10px;
      gap: 6px;
    }
    .viz-info {
      margin-left: 0;
      width: 100%;
      justify-content: space-between;
      font-size: 9px;
    }
    .viz-mode-btn {
      padding: 6px 10px;
      font-size: 9px;
      letter-spacing: 0.15em;
    }

    .viz-stage { min-height: 420px; }
    .viz-sidebar { max-height: none; }
    .viz-sidebar textarea { min-height: 140px; }

    .viz-legend {
      bottom: 8px; left: 8px;
      padding: 6px 8px;
    }
    .viz-legend .legend-row { font-size: 9px; }
    .viz-legend .legend-title { font-size: 8px; }

    .viz-popover {
      max-width: calc(100vw - 32px);
      font-size: 10px;
    }

    /* Validation */
    .validation li { font-size: 10px; word-break: break-word; }

    /* Toast - full width on phones */
    .toast {
      left: 12px; right: 12px; bottom: 12px;
      transform: translateY(100px);
    }
    .toast.show { transform: translateY(0); }
  }

  /* Very small phones - 380px and below */
  @media (max-width: 380px) {
    main { padding: 12px 10px; }
    .topbar { padding: 6px 10px; }
    .tab { padding: 10px 10px; font-size: 9px; }
    .panel h1 { font-size: 20px; }
    .card { padding: 12px 14px; }
    .pill { font-size: 8px; padding: 3px 8px; letter-spacing: 0.1em; }
  }

  /* Touch devices - larger tap targets */
  @media (hover: none) and (pointer: coarse) {
    .btn, .tab, .remove-btn, .chip-x,
    input[type="text"], select {
      min-height: 36px;
    }
    .btn.small { min-height: 30px; }
    .remove-btn { padding: 8px; min-width: 32px; }
  }

</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <svg class="brand-logo" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
      <!-- Bottom chevron (widest) -->
      <path d="M 30,150 L 100,180 L 170,150 L 170,170 L 100,200 L 30,170 Z" fill="#2F6BFF" opacity="0.45"/>
      <!-- Middle chevron -->
      <path d="M 45,115 L 100,140 L 155,115 L 155,135 L 100,160 L 45,135 Z" fill="#2F6BFF" opacity="0.75"/>
      <!-- Top chevron (narrowest) -->
      <path d="M 60,80 L 100,100 L 140,80 L 140,100 L 100,120 L 60,100 Z" fill="#2F6BFF"/>
      <!-- Plankton capstone marker -->
      <circle cx="100" cy="55" r="12" fill="#3ad0a8"/>
    </svg>
    <div>
      <div class="brand-text">IIM <em>Workbench</em></div>
      <div class="brand-tag">Chain Builder · Validator · STIX Export</div>
    </div>
  </div>
  <div class="status-pills">
    <span class="pill"><a style="color: inherit; text-decoration: inherit" target="_blank" href="https://github.com/MalwareboxEU/IIM-Workbench">GitHub</a></span>
    <span class="pill">Spec {{ spec_version }}</span>
    <span class="pill">Catalog {{ catalog_version }}</span>
    <span class="pill">{{ technique_count }} Techniques</span>
    <span class="pill live">Local</span>
  </div>
</div>

<div class="tabs">
  <div class="tab active" data-tab="builder">Chain Builder</div>
  <div class="tab" data-tab="visualize">Visualize</div>
  <div class="tab" data-tab="interop">Interop</div>
  <div class="tab" data-tab="techniques">Technique Catalog <span class="count">{{ technique_count }}</span></div>
  <div class="tab" data-tab="validator">Validator</div>
  <div class="tab" data-tab="help">Help</div>

</div>

<main>

  <!-- ======================= BUILDER PANEL ======================= -->
  <section class="panel active" id="panel-builder">
    <h1>Build a <em>chain</em>.</h1>
    <p class="lead">
      Add entities you observed, assign them to role positions in the chain, annotate with techniques,
      and declare the relations between them. The Workbench validates as you go and can export the
      result as a pattern or a STIX&nbsp;2.1 bundle.
    </p>

    <div class="builder-grid">
      <!-- LEFT COLUMN: Input forms -->
      <div>
        <!-- Meta card -->
        <div class="card">
          <div class="card-head">
            <h3>Metadata <span class="badge">Step 1</span></h3>
            <div class="card-actions">
              <button class="btn small" onclick="loadExample()">Load Example</button>
              <button class="btn small danger" onclick="clearAll()">Clear</button>
            </div>
          </div>
          <div class="field-row">
            <div class="field">
              <label>Chain ID</label>
              <input type="text" id="chain-id" placeholder="gamaredon-2026-01-13">
            </div>
            <div class="field">
              <label>IIM Version</label>
              <input type="text" id="iim-version" value="1.1">
            </div>
          </div>
          <div class="field-row">
            <div class="field">
              <label>Confidence</label>
              <select id="confidence">
                <option value="">- (not set)</option>
                <option value="confirmed">Confirmed</option>
                <option value="likely">Likely</option>
                <option value="tentative">Tentative</option>
              </select>
            </div>
            <div class="field">
              <label>Observed At (optional)</label>
              <input type="text" id="observed-at" placeholder="2026-01-13T14:22:00Z">
            </div>
          </div>
        </div>

        <!-- Entities card -->
        <div class="card" style="margin-top: 16px;">
          <div class="card-head">
            <h3>Entities <span class="badge">Step 2</span></h3>
            <div class="card-actions">
              <button class="btn small primary" onclick="addEntity()">+ Add Entity</button>
            </div>
          </div>
          <div class="entity-list" id="entity-list"></div>
        </div>

        <!-- Chain positions card -->
        <div class="card" style="margin-top: 16px;">
          <div class="card-head">
            <h3>Chain Positions <span class="badge">Step 3</span></h3>
            <div class="card-actions">
              <button class="btn small primary" onclick="addChainPos()">+ Add Position</button>
            </div>
          </div>
          <div class="chain-list" id="chain-list"></div>
        </div>

        <!-- Relations card -->
        <div class="card" style="margin-top: 16px;">
          <div class="card-head">
            <h3>Relations <span class="badge">Step 4</span></h3>
            <div class="card-actions">
              <button class="btn small primary" onclick="addRelation()">+ Add Relation</button>
            </div>
          </div>
          <div class="rel-list" id="rel-list"></div>
        </div>
      </div>

      <!-- RIGHT COLUMN: Output and actions -->
      <div>
        <div class="card">
          <div class="card-head">
            <h3>Generated JSON</h3>
            <div class="card-actions">
              <button class="btn small" onclick="validateChain()">Validate</button>
              <button class="btn small" onclick="copyJson()">Copy</button>
              <button class="btn small" onclick="downloadJson()">Download</button>
            </div>
          </div>
          <div class="json-output" id="json-output">// Your chain appears here as you build it</div>
          <div id="validation-result"></div>
        </div>

        <div class="card" style="margin-top: 16px;">
          <div class="card-head">
            <h3>Export</h3>
          </div>
          <p style="font-size: 11px; color: var(--bone-dim); margin-bottom: 14px;">
            Convert the chain into a reusable pattern (for publishing as a feed) or into a STIX 2.1 bundle (for MISP, OpenCTI, TAXII servers).
          </p>
          <div class="field-row">
            <button class="btn primary" onclick="exportPattern()" style="justify-content: center;">-> Pattern</button>
            <button class="btn primary" onclick="exportStix()" style="justify-content: center;">-> STIX 2.1</button>
          </div>
        </div>

        <div class="help-snippet">
          <b>Quick tip:</b> Entity IDs (like <code>e1</code>, <code>e2</code>) are your shorthand - use them to reference entities in Chain Positions and Relations. The Workbench re-maps everything on export.
        </div>
      </div>
    </div>
  </section>

  <!-- ======================= VISUALIZE PANEL ======================= -->
  <section class="panel" id="panel-visualize">
    <h1>Visualize a <em>chain</em> or pattern.</h1>
    <p class="lead">
      Render IIM chains and patterns as interactive diagrams. Switch between linear flow (chain-like) and graph (relation-rich) modes. Paste JSON, load from the Chain Builder, or pick from the reference library.
    </p>

    <div class="viz-layout">
      <!-- Sidebar -->
      <div class="viz-sidebar">
        <div class="card">
          <div class="card-head">
            <h3>Input <span class="badge">JSON</span></h3>
          </div>
          <div style="display: flex; gap: 6px; margin-bottom: 10px;">
            <button class="btn small primary" onclick="vizFromBuilder()">From Builder</button>
            <button class="btn small" onclick="vizParseInput()">Render JSON</button>
          </div>
          <textarea id="viz-input" placeholder="Paste chain or pattern JSON, or click 'From Builder' / load an example below"></textarea>
        </div>

        <div class="card">
          <div class="card-head">
            <h3>Reference Library</h3>
          </div>
          <p style="font-size: 10px; color: var(--bone-darker); margin-bottom: 10px;">
            Click any entry to load it into the visualizer.
          </p>
          <div class="example-list" id="example-list"></div>
        </div>

        <div class="card">
          <div class="card-head">
            <h3>Export</h3>
          </div>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <button class="btn small" onclick="vizExportSvg()">Download SVG</button>
            <button class="btn small" onclick="vizExportPng()">Download PNG</button>
          </div>
          <p style="font-size: 10px; color: var(--bone-darker); margin-top: 10px;">
            SVG preserves crisp quality at any size. PNG is rasterized at current viewport.
          </p>
        </div>
      </div>

      <!-- Stage -->
      <div class="viz-stage">
        <div class="viz-toolbar">
          <div class="viz-mode-group">
            <button class="viz-mode-btn active" id="viz-mode-flow" onclick="vizSetMode('flow')">Flow</button>
            <button class="viz-mode-btn" id="viz-mode-graph" onclick="vizSetMode('graph')">Graph</button>
          </div>
          <button class="btn small" onclick="vizFit()" title="Fit to view">⊹ Fit</button>
          <button class="btn small" onclick="vizZoom(1.2)">+</button>
          <button class="btn small" onclick="vizZoom(0.833)">−</button>
          <button class="btn small" onclick="vizReset()">Reset</button>
          <div class="viz-info" id="viz-info">
            <span class="kv"><span class="k">Positions</span><span class="v" id="viz-stat-pos">-</span></span>
            <span class="kv"><span class="k">Relations</span><span class="v" id="viz-stat-rel">-</span></span>
            <span class="kv"><span class="k">Techniques</span><span class="v" id="viz-stat-tech">-</span></span>
          </div>
        </div>
        <div class="viz-canvas-wrap" id="viz-canvas-wrap">
          <svg class="viz-svg" id="viz-svg" xmlns="http://www.w3.org/2000/svg"></svg>
          <div class="viz-empty" id="viz-empty">
            <h4>Nothing to visualize yet</h4>
            <p>Paste a chain or pattern on the left, import from the Chain Builder, or pick one from the reference library.</p>
          </div>
          <div class="viz-legend" id="viz-legend" style="display: none;">
            <div class="legend-title">Roles</div>
            <div class="legend-row"><span class="legend-swatch legend-entry"></span><span>Entry</span></div>
            <div class="legend-row"><span class="legend-swatch legend-redirector"></span><span>Redirector</span></div>
            <div class="legend-row"><span class="legend-swatch legend-staging"></span><span>Staging</span></div>
            <div class="legend-row"><span class="legend-swatch legend-payload"></span><span>Payload</span></div>
            <div class="legend-row"><span class="legend-swatch legend-c2"></span><span>C2</span></div>
          </div>
          <div class="viz-popover" id="viz-popover">
            <button class="pop-close" onclick="vizClosePopover()">✕</button>
            <div id="viz-popover-content"></div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- ======================= INTEROP PANEL ======================= -->
  <section class="panel" id="panel-interop">
    <h1>Interop · <em>STIX 2.1</em>.</h1>
    <p class="lead">
      Convert between IIM chains and STIX 2.1 bundles in both directions.
      <strong style="color: var(--bone);">IIM -> STIX is lossless</strong> - every IIM concept survives with <code>x_iim_*</code> custom properties.
      <strong style="color: var(--amber);">STIX -> IIM is an enrichment workflow</strong> - STIX lacks role semantics, ordered chains, and infrastructure techniques, so the import infers what it can, marks everything uncertain, and produces a report of what needs analyst review.
    </p>

    <div class="builder-grid">
      <!-- LEFT: Input -->
      <div>
        <div class="card">
          <div class="card-head">
            <h3>Direction <span class="badge">Step 1</span></h3>
          </div>
          <div style="display: flex; gap: 0; border: 1px solid var(--ink); border-radius: 2px; margin-bottom: 16px;">
            <button id="interop-dir-export" class="btn small" onclick="interopSetDir('export')" style="flex:1; border: none; border-right: 1px solid var(--ink); border-radius: 0;">IIM -> STIX</button>
            <button id="interop-dir-import" class="btn small" onclick="interopSetDir('import')" style="flex:1; border: none; border-radius: 0;">STIX -> IIM</button>
          </div>
          <p id="interop-dir-desc" style="font-size: 11px; color: var(--bone-dim); line-height: 1.7;"></p>
        </div>

        <div class="card" style="margin-top: 16px;">
          <div class="card-head">
            <h3 id="interop-input-title">Input</h3>
            <div class="card-actions">
              <button class="btn small" onclick="interopFromBuilder()" id="interop-from-builder">From Builder</button>
              <button class="btn small" onclick="interopLoadExample()">Load Example</button>
              <button class="btn small" onclick="document.getElementById('interop-input').value='';interopClearOutput()">Clear</button>
            </div>
          </div>
          <textarea id="interop-input" placeholder="Paste JSON here, import from the Chain Builder, or load an example." style="min-height: 340px;"></textarea>
          <div style="margin-top: 14px; display: flex; gap: 8px;">
            <button class="btn primary" onclick="interopRun()" id="interop-run-btn" style="flex: 1; justify-content: center;">Convert</button>
          </div>
        </div>
      </div>

      <!-- RIGHT: Output + report -->
      <div>
        <div class="card">
          <div class="card-head">
            <h3 id="interop-output-title">Output</h3>
            <div class="card-actions">
              <button class="btn small" onclick="interopCopyOutput()">Copy</button>
              <button class="btn small" onclick="interopDownloadOutput()">Download</button>
            </div>
          </div>
          <div class="json-output" id="interop-output" style="min-height: 200px;">// Output will appear here after conversion</div>
        </div>

        <div class="card" style="margin-top: 16px; display: none;" id="interop-report-card">
          <div class="card-head">
            <h3>Import Report</h3>
          </div>
          <div id="interop-report"></div>
        </div>

        <div class="help-snippet" style="margin-top: 16px;">
          <b>About STIX imports:</b> roles inferred from STIX <code>infrastructure_types</code> and techniques recovered from attack-pattern references are marked <code>tentative</code>. Any chain with inferred annotations carries <code>needs_review: true</code> - treat it as a starting point, not a finished analysis.
        </div>
      </div>
    </div>
  </section>

  <!-- ======================= TECHNIQUES PANEL ======================= -->
  <section class="panel" id="panel-techniques">
    <h1>Technique <em>catalog</em>.</h1>
    <p class="lead">
      Browse all {{ technique_count }} infrastructure techniques defined in IIM v1.0. Search by ID, name, or keyword. Click any card for the full definition, indicators, and examples.
    </p>

    <div class="tech-controls">
      <input type="text" id="tech-search" placeholder="Search - e.g. 'dns', 'geofence', 'rotation'...">
      <select id="tech-filter">
        <option value="">All Categories</option>
        <option value="hosting">Hosting</option>
        <option value="resolution">Resolution</option>
        <option value="routing">Routing</option>
        <option value="gating">Gating</option>
        <option value="composition">Composition</option>
      </select>
    </div>

    <div class="tech-grid" id="tech-grid"></div>
  </section>

  <!-- ======================= VALIDATOR PANEL ======================= -->
  <section class="panel" id="panel-validator">
    <h1>Validate <em>any</em> chain or pattern.</h1>
    <p class="lead">
      Paste an existing IIM chain or pattern JSON on the left. The Workbench runs a full structural check - entity references, role validity, technique IDs against the loaded catalog, relation integrity, sequence ordering.
    </p>

    <div class="validator-grid">
      <div class="card validator-input">
        <div class="card-head">
          <h3>Input JSON</h3>
          <div class="card-actions">
            <button class="btn small" onclick="validatorMode('chain')" id="vmode-chain">Chain</button>
            <button class="btn small" onclick="validatorMode('pattern')" id="vmode-pattern">Pattern</button>
          </div>
        </div>
        <textarea id="validator-input" placeholder='Paste your IIM chain or pattern JSON here...'></textarea>
        <div style="margin-top: 12px; display: flex; gap: 8px;">
          <button class="btn primary" onclick="runValidation()">Validate</button>
          <button class="btn small" onclick="document.getElementById('validator-input').value=''">Clear</button>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h3>Result</h3>
        </div>
        <div id="validator-result" style="font-size: 11px; color: var(--bone-dim);">
          <p>Paste JSON and click Validate to see results here.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- ======================= HELP PANEL ======================= -->
  <section class="panel" id="panel-help">
    <h1>How this <em>works</em>.</h1>
    <p class="lead">
      The IIM Workbench is a local tool for building and validating IIM chains and patterns. Nothing leaves your machine - the Flask server runs on localhost and the technique catalog is loaded from a local JSON file.
    </p>

    <div class="card">
      <div class="card-head"><h3>What you can do</h3></div>
      <ul style="padding-left: 20px; font-size: 12px; color: var(--bone-dim); line-height: 1.9;">
        <li><b style="color: var(--plankton);">Build a chain</b> - add entities, assign role positions, annotate techniques, declare relations. The JSON output updates live.</li>
        <li><b style="color: var(--plankton);">Browse techniques</b> - full searchable catalog with definitions, indicators, examples, and ATT&amp;CK cross-references.</li>
        <li><b style="color: var(--plankton);">Validate</b> - paste any IIM chain or pattern and get a structured validation report with errors and warnings.</li>
        <li><b style="color: var(--plankton);">Export to pattern</b> - abstract a concrete chain into a reusable feed pattern (entity values stripped, shape preserved).</li>
        <li><b style="color: var(--plankton);">Export to STIX 2.1</b> - complete bundle with Infrastructure, Indicator, Attack-Pattern, and Relationship objects. Deterministic UUIDs make round-trips stable.</li>
      </ul>
    </div>

    <div class="card" style="margin-top: 16px;">
      <div class="card-head"><h3>API endpoints</h3></div>
      <div style="font-family: var(--font-mono); font-size: 11px; color: var(--bone-dim); line-height: 2;">
        <div><span style="color: var(--amber);">GET</span>  <code>/api/health</code> &nbsp;- liveness + catalog version</div>
        <div><span style="color: var(--amber);">GET</span>  <code>/api/catalog</code> &nbsp;- full technique catalog</div>
        <div><span style="color: var(--amber);">GET</span>  <code>/api/techniques?q=&lt;search&gt;&amp;category=&lt;cat&gt;</code></div>
        <div><span style="color: var(--amber);">GET</span>  <code>/api/techniques/&lt;ID&gt;</code> &nbsp;- e.g. <code>/api/techniques/IIM-T019</code></div>
        <div><span style="color: var(--plankton);">POST</span> <code>/api/validate/chain</code> &nbsp;- body: chain JSON</div>
        <div><span style="color: var(--plankton);">POST</span> <code>/api/validate/pattern</code> &nbsp;- body: pattern JSON</div>
        <div><span style="color: var(--plankton);">POST</span> <code>/api/export/stix</code> &nbsp;- body: chain JSON -> STIX bundle</div>
        <div><span style="color: var(--plankton);">POST</span> <code>/api/export/pattern</code> &nbsp;- body: {chain, pattern_id, name, match_semantics}</div>
      </div>
    </div>

    <div class="card" style="margin-top: 16px;">
      <div class="card-head"><h3>CLI mode</h3></div>
      <div style="font-family: var(--font-mono); font-size: 11px; color: var(--bone-dim); line-height: 1.9;">
        <p><code>python iim_workbench.py</code> - start the server (default port 5000)</p>
        <p><code>python iim_workbench.py --port 8080</code> - custom port</p>
        <p><code>python iim_workbench.py --validate chain.json</code> - validate from CLI, exit 0/1</p>
        <p><code>python iim_workbench.py --stix chain.json</code> - export to STIX and print</p>
        <p><code>python iim_workbench.py --catalog /path/to/catalog.json</code> - custom catalog location</p>
      </div>
    </div>
  </section>
</main>

<!-- Technique detail modal -->
<div class="modal-backdrop" id="tech-modal">
  <div class="modal" id="modal-body"></div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
// =========================================================================
// STATE
// =========================================================================
const state = {
  entities: [],
  chain: [],
  relations: [],
  catalog: null,
  entityCounter: 1,
  validatorMode: 'chain',
};

// =========================================================================
// INIT
// =========================================================================
async function init() {
  // Load catalog
  try {
    const res = await fetch('/api/catalog');
    state.catalog = await res.json();
    renderTechniques();
  } catch (e) {
    toast('Failed to load technique catalog', 'error');
  }

  // Tabs
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });

  // Technique search
  document.getElementById('tech-search').addEventListener('input', renderTechniques);
  document.getElementById('tech-filter').addEventListener('change', renderTechniques);

  // Close modal on backdrop click
  document.getElementById('tech-modal').addEventListener('click', (e) => {
    if (e.target.id === 'tech-modal') closeModal();
  });

  // Render visualization example library
  vizRenderExampleList();

  // Set default interop direction
  interopSetDir('export');
  validatorMode('chain');

  updateOutput();
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + name));
}

// =========================================================================
// ENTITIES
// =========================================================================
function addEntity(data = {}) {
  const id = data.id || `e${state.entityCounter++}`;
  state.entities.push({
    id, type: data.type || 'url', value: data.value || ''
  });
  renderEntities();
  updateOutput();
}

function removeEntity(idx) {
  const removed = state.entities.splice(idx, 1)[0];
  if (removed) {
    // Cascading cleanup
    state.chain = state.chain.filter(p => p.entity_id !== removed.id);
    state.relations = state.relations.filter(r => r.from !== removed.id && r.to !== removed.id);
  }
  renderEntities(); renderChainList(); renderRelations();
  updateOutput();
}

function updateEntity(idx, field, value) {
  state.entities[idx][field] = value;
  if (field === 'id') {
    // update refs
    const oldId = state.entities[idx]._lastId || state.entities[idx].id;
    renderChainList();
    renderRelations();
  }
  updateOutput();
}

function renderEntities() {
  const el = document.getElementById('entity-list');
  if (state.entities.length === 0) {
    el.innerHTML = '<div style="padding: 12px; color: var(--bone-darker); font-size: 11px; text-align: center;">No entities yet. Click + Add Entity to start.</div>';
    return;
  }
  el.innerHTML = state.entities.map((e, i) => `
    <div class="entity-row">
      <input type="text" class="id-field" value="${escapeHtml(e.id)}" onchange="updateEntity(${i}, 'id', this.value)">
      <select onchange="updateEntity(${i}, 'type', this.value)">
        ${['url','domain','ip','file','hash','email','certificate','asn'].map(t =>
          `<option value="${t}" ${e.type===t?'selected':''}>${t}</option>`).join('')}
      </select>
      <input type="text" value="${escapeHtml(e.value)}" placeholder="value (e.g. c2.duckdns.org)" onchange="updateEntity(${i}, 'value', this.value)">
      <button class="remove-btn" onclick="removeEntity(${i})" title="Remove">✕</button>
    </div>
  `).join('');
}

// =========================================================================
// CHAIN POSITIONS
// =========================================================================
function addChainPos(data = {}) {
  state.chain.push({
    entity_id: data.entity_id || (state.entities[0]?.id || ''),
    role: data.role || 'entry',
    techniques: data.techniques || [],
  });
  renderChainList(); updateOutput();
}
function removeChainPos(idx) {
  state.chain.splice(idx, 1); renderChainList(); updateOutput();
}
function updateChainPos(idx, field, value) {
  state.chain[idx][field] = value; renderChainList(); updateOutput();
}
function addTechToPos(idx) {
  const input = prompt('Technique ID (e.g. IIM-T019):');
  if (!input) return;
  const clean = input.trim().toUpperCase();
  if (!/^IIM-T\d{3}$/.test(clean)) {
    toast('Invalid format. Expected IIM-T###', 'error'); return;
  }
  state.chain[idx].techniques.push(clean);
  renderChainList(); updateOutput();
}
function removeTechFromPos(posIdx, techIdx) {
  state.chain[posIdx].techniques.splice(techIdx, 1);
  renderChainList(); updateOutput();
}
function renderChainList() {
  const el = document.getElementById('chain-list');
  if (state.chain.length === 0) {
    el.innerHTML = '<div style="padding: 12px; color: var(--bone-darker); font-size: 11px; text-align: center;">No chain positions yet.</div>';
    return;
  }
  const entOptions = state.entities.map(e =>
    `<option value="${e.id}">${e.id} - ${escapeHtml(e.value || '(empty)')}</option>`).join('');
  el.innerHTML = state.chain.map((p, i) => `
    <div class="chain-pos" data-role="${p.role}">
      <div class="pos-idx">${i}</div>
      <select onchange="updateChainPos(${i}, 'entity_id', this.value)">
        <option value="">- select entity -</option>
        ${entOptions.replaceAll(`value="${p.entity_id}"`, `value="${p.entity_id}" selected`)}
      </select>
      <select onchange="updateChainPos(${i}, 'role', this.value)">
        ${['entry','redirector','staging','payload','c2'].map(r =>
          `<option value="${r}" ${p.role===r?'selected':''}>${r}</option>`).join('')}
      </select>
      <div class="tech-chips" onclick="if(event.target.classList.contains('tech-chips'))addTechToPos(${i})">
        ${p.techniques.map((t, tIdx) => `
          <span class="chip">${t}<span class="chip-x" onclick="event.stopPropagation(); removeTechFromPos(${i}, ${tIdx})">✕</span></span>
        `).join('')}
        ${p.techniques.length === 0 ? '<span style="color: var(--bone-darker); font-size: 10px;">+ click to add technique</span>' : ''}
      </div>
      <button class="remove-btn" onclick="removeChainPos(${i})" title="Remove">✕</button>
    </div>
  `).join('');
}

// =========================================================================
// RELATIONS
// =========================================================================
function addRelation(data = {}) {
  state.relations.push({
    from: data.from || (state.entities[0]?.id || ''),
    to: data.to || (state.entities[1]?.id || ''),
    type: data.type || 'download',
    sequence_order: data.sequence_order ?? state.relations.length + 1,
  });
  renderRelations(); updateOutput();
}
function removeRelation(idx) { state.relations.splice(idx, 1); renderRelations(); updateOutput(); }
function updateRelation(idx, field, value) {
  if (field === 'sequence_order') state.relations[idx][field] = parseInt(value) || 0;
  else state.relations[idx][field] = value;
  updateOutput();
}
function renderRelations() {
  const el = document.getElementById('rel-list');
  if (state.relations.length === 0) {
    el.innerHTML = '<div style="padding: 12px; color: var(--bone-darker); font-size: 11px; text-align: center;">No relations yet.</div>';
    return;
  }
  const entOptions = state.entities.map(e =>
    `<option value="${e.id}">${e.id}</option>`).join('');
  el.innerHTML = state.relations.map((r, i) => `
    <div class="rel-row">
      <select onchange="updateRelation(${i}, 'from', this.value)">
        ${entOptions.replaceAll(`value="${r.from}"`, `value="${r.from}" selected`)}
      </select>
      <select onchange="updateRelation(${i}, 'type', this.value)">
        ${['download','redirect','drops','execute','connect','resolves-to','references','communicates-with'].map(t =>
          `<option value="${t}" ${r.type===t?'selected':''}>${t}</option>`).join('')}
      </select>
      <select onchange="updateRelation(${i}, 'to', this.value)">
        ${entOptions.replaceAll(`value="${r.to}"`, `value="${r.to}" selected`)}
      </select>
      <input type="number" value="${r.sequence_order}" onchange="updateRelation(${i}, 'sequence_order', this.value)" title="sequence order">
      <button class="remove-btn" onclick="removeRelation(${i})" title="Remove">✕</button>
    </div>
  `).join('');
}

// =========================================================================
// OUTPUT / VALIDATION / EXPORT
// =========================================================================
function buildChainJson() {
  const obj = {
    iim_version: document.getElementById('iim-version').value || '1.1',
    chain_id: document.getElementById('chain-id').value || 'unnamed-chain',
    entities: state.entities,
    chain: state.chain,
    relations: state.relations,
  };
  const conf = document.getElementById('confidence').value;
  if (conf) obj.confidence = conf;
  const obsAt = document.getElementById('observed-at').value;
  if (obsAt) obj.observed_at = obsAt;
  return obj;
}

function updateOutput() {
  const chain = buildChainJson();
  const json = JSON.stringify(chain, null, 2);
  document.getElementById('json-output').innerHTML = syntaxHighlight(json);
}

async function validateChain() {
  const chain = buildChainJson();
  try {
    const res = await fetch('/api/validate/chain', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(chain),
    });
    const data = await res.json();
    renderValidation(data, 'validation-result');
  } catch (e) {
    toast('Validation failed: ' + e.message, 'error');
  }
}

function renderValidation(data, targetId) {
  const target = document.getElementById(targetId);
  const errCount = (data.errors || []).length;
  const warnCount = (data.warnings || []).length;
  let html = `<div class="validation ${data.valid ? 'valid' : 'invalid'}">`;
  html += `<h4>${data.valid ? '✓ Valid' : '✗ Invalid'} &middot; ${errCount} error${errCount!==1?'s':''}, ${warnCount} warning${warnCount!==1?'s':''}</h4>`;
  if (errCount > 0) {
    html += '<ul>';
    for (const e of data.errors) {
      html += `<li class="err"><span class="path">[ERROR]</span> <b>${escapeHtml(e.path)}</b> - ${escapeHtml(e.message)}</li>`;
    }
    html += '</ul>';
  }
  if (warnCount > 0) {
    html += '<ul>';
    for (const w of data.warnings) {
      html += `<li class="warn"><span class="path">[WARN]</span> <b>${escapeHtml(w.path)}</b> - ${escapeHtml(w.message)}</li>`;
    }
    html += '</ul>';
  }
  if (errCount === 0 && warnCount === 0) {
    html += '<p style="color: var(--plankton); font-size: 11px;">All checks passed cleanly.</p>';
  }
  html += '</div>';
  target.innerHTML = html;
}

async function exportStix() {
  const chain = buildChainJson();
  const res = await fetch('/api/export/stix', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(chain),
  });
  const data = await res.json();
  if (data.error) {
    toast('Export failed: ' + data.error, 'error');
    if (data.validation) renderValidation(data.validation, 'validation-result');
    return;
  }
  downloadFile(JSON.stringify(data, null, 2), `${chain.chain_id}-stix.json`, 'application/json');
  toast('STIX bundle downloaded');
}

async function exportPattern() {
  const chain = buildChainJson();
  const pid = prompt('Pattern ID (e.g. MB-F-0023):', 'MB-F-0001');
  if (!pid) return;
  const name = prompt('Pattern name:', 'Derived Pattern');
  if (!name) return;
  const res = await fetch('/api/export/pattern', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain, pattern_id: pid, name, match_semantics: 'structural' }),
  });
  const data = await res.json();
  if (data.error) { toast('Export failed: ' + data.error, 'error'); return; }
  downloadFile(JSON.stringify(data, null, 2), `${pid}.json`, 'application/json');
  toast('Pattern downloaded');
}

function copyJson() {
  const chain = buildChainJson();
  navigator.clipboard.writeText(JSON.stringify(chain, null, 2));
  toast('Copied to clipboard');
}
function downloadJson() {
  const chain = buildChainJson();
  downloadFile(JSON.stringify(chain, null, 2), `${chain.chain_id}.json`, 'application/json');
  toast('Chain downloaded');
}

// =========================================================================
// VALIDATOR TAB
// =========================================================================
function validatorMode(mode) {
  state.validatorMode = mode;
  document.getElementById('vmode-chain').classList.toggle('primary', mode === 'chain');
  document.getElementById('vmode-pattern').classList.toggle('primary', mode === 'pattern');
}

async function runValidation() {
  const txt = document.getElementById('validator-input').value;
  let parsed;
  try { parsed = JSON.parse(txt); }
  catch (e) {
    document.getElementById('validator-result').innerHTML =
      `<div class="validation invalid"><h4>✗ Invalid JSON</h4><p>${escapeHtml(e.message)}</p></div>`;
    return;
  }

  // Auto-detect type from JSON shape (same heuristic as vizLoadData)
  const looksLikePattern = parsed.pattern_id !== undefined && Array.isArray(parsed.shape);
  const looksLikeChain   = Array.isArray(parsed.entities) && Array.isArray(parsed.chain);

  let mode = state.validatorMode;
  if (looksLikePattern && !looksLikeChain)      mode = 'pattern';
  else if (looksLikeChain && !looksLikePattern) mode = 'chain';
  // ambiguous or unrecognized → respect manual toggle

  // Sync the toggle so the user sees which validator actually ran
  validatorMode(mode);

  const endpoint = mode === 'pattern' ? '/api/validate/pattern' : '/api/validate/chain';
  const res = await fetch(endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(parsed),
  });
  const data = await res.json();
  renderValidation(data, 'validator-result');
}
// =========================================================================
// TECHNIQUES TAB
// =========================================================================
function renderTechniques() {
  if (!state.catalog) return;
  const q = document.getElementById('tech-search').value.toLowerCase();
  const cat = document.getElementById('tech-filter').value;
  let techs = state.catalog.techniques || [];
  if (q) techs = techs.filter(t =>
    t.id.toLowerCase().includes(q) ||
    t.name.toLowerCase().includes(q) ||
    (t.short || '').toLowerCase().includes(q) ||
    (t.description || '').toLowerCase().includes(q)
  );
  if (cat) techs = techs.filter(t => t.category === cat);

  const grid = document.getElementById('tech-grid');
  if (techs.length === 0) {
    grid.innerHTML = '<div style="grid-column: 1/-1; padding: 32px; text-align: center; color: var(--bone-darker);">No techniques match your filter.</div>';
    return;
  }
  grid.innerHTML = techs.map(t => `
    <div class="tech-card" onclick="showTechnique('${t.id}')">
      <div class="t-id">${t.id}</div>
      <div class="t-name">${escapeHtml(t.name)}</div>
      <span class="t-cat">${t.category}</span>
      <div class="t-short">${escapeHtml(t.short || '')}</div>
    </div>
  `).join('');
}

function showTechnique(tid) {
  const t = state.catalog.techniques.find(x => x.id === tid);
  if (!t) return;
  const body = document.getElementById('modal-body');
  body.innerHTML = `
    <button class="close" onclick="closeModal()">✕</button>
    <div class="m-id">${t.id} · ${t.category.toUpperCase()}</div>
    <h2>${escapeHtml(t.name)}</h2>
    <p>${escapeHtml(t.short || '')}</p>

    <h4>Description</h4>
    <p>${escapeHtml(t.description || '')}</p>

    ${t.why_infrastructure ? `<h4>Why This Is Infrastructure</h4><div class="why">${escapeHtml(t.why_infrastructure)}</div>` : ''}

    ${t.observable_indicators ? `
      <h4>Observable Indicators</h4>
      <ul>${t.observable_indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>
    ` : ''}

    ${t.example ? `<h4>Example</h4><div class="example">${escapeHtml(t.example)}</div>` : ''}

    ${t.detection_notes ? `<h4>Detection Notes</h4><p>${escapeHtml(t.detection_notes)}</p>` : ''}

    ${t.attack_related && t.attack_related.length ? `
      <h4>Related ATT&amp;CK Techniques</h4>
      <p>${t.attack_related.map(a => `<span class="chip">${a}</span>`).join(' ')}</p>
      <p style="font-size: 10px; color: var(--bone-darker); margin-top: 8px;">
        Note: these are <em>conceptually adjacent</em> - not equivalences. ATT&amp;CK describes endpoint behavior; IIM describes infrastructure.
      </p>
    ` : ''}

    <h4>Introduced in</h4>
    <p>Catalog version ${t.introduced_in || '?'}</p>
  `;
  document.getElementById('tech-modal').classList.add('active');
}
function closeModal() { document.getElementById('tech-modal').classList.remove('active'); }

// =========================================================================
// UTILITIES
// =========================================================================
function syntaxHighlight(json) {
  return json
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      function (match) {
        let cls = 'num';
        if (/^"/.test(match)) cls = /:$/.test(match) ? 'key' : 'str';
        else if (/true|false/.test(match)) cls = 'bool';
        else if (/null/.test(match)) cls = 'bool';
        return '<span class="' + cls + '">' + match + '</span>';
      });
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
function toast(msg, kind = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast ' + kind;
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => el.classList.remove('show'), 2600);
}

// =========================================================================
// EXAMPLE / RESET
// =========================================================================
function loadExample() {
  state.entities = [
    { id: 'e1', type: 'url',    value: 'https://phish.example/lure.pdf' },
    { id: 'e2', type: 'file',   value: 'lure.rar' },
    { id: 'e3', type: 'file',   value: 'loader.hta' },
    { id: 'e4', type: 'file',   value: 'pteranodon.exe' },
    { id: 'e5', type: 'domain', value: 'c2.duckdns.org' },
  ];
  state.entityCounter = 6;
  state.chain = [
    { entity_id: 'e1', role: 'entry',   techniques: ['IIM-T019'] },
    { entity_id: 'e2', role: 'staging', techniques: ['IIM-T024'] },
    { entity_id: 'e3', role: 'staging', techniques: ['IIM-T021'] },
    { entity_id: 'e4', role: 'payload', techniques: [] },
    { entity_id: 'e5', role: 'c2',      techniques: ['IIM-T008', 'IIM-T011', 'IIM-T013'] },
  ];
  state.relations = [
    { from: 'e1', to: 'e2', type: 'download', sequence_order: 1 },
    { from: 'e2', to: 'e3', type: 'drops',    sequence_order: 2 },
    { from: 'e3', to: 'e4', type: 'execute',  sequence_order: 3 },
    { from: 'e4', to: 'e5', type: 'connect',  sequence_order: 4 },
  ];
  document.getElementById('chain-id').value = 'gamaredon-2026-01-13';
  document.getElementById('iim-version').value = '1.1';
  document.getElementById('confidence').value = 'confirmed';
  renderEntities(); renderChainList(); renderRelations();
  updateOutput();
  toast('Example loaded (Gamaredon Jan 2026)');
}
function clearAll() {
  if (!confirm('Clear all entities, chain positions, and relations?')) return;
  state.entities = []; state.chain = []; state.relations = []; state.entityCounter = 1;
  document.getElementById('chain-id').value = '';
  document.getElementById('confidence').value = '';
  document.getElementById('observed-at').value = '';
  renderEntities(); renderChainList(); renderRelations();
  updateOutput();
  toast('Cleared');
}

// =========================================================================
// VISUALIZATION
// =========================================================================
const vizState = {
  data: null,          // normalized { positions: [{id, role, techniques, entity}], relations: [{from, to, type, seq}] }
  isPattern: false,
  mode: 'flow',
  pan: { x: 0, y: 0 },
  zoom: 1,
  dragging: false,
  dragStart: null,
};

// Reference chains - curated library
const VIZ_EXAMPLES = [
  {
    name: 'Gamaredon · RAR-HTA Delivery (MB-0001)',
    tag: 'chain · Jan 2026',
    data: {
      iim_version: '1.1', chain_id: 'gamaredon-2026-01-13',
      entities: [
        { id: 'e1', type: 'url',    value: 'https://phish.example/lure.pdf' },
        { id: 'e2', type: 'file',   value: 'lure.rar' },
        { id: 'e3', type: 'file',   value: 'loader.hta' },
        { id: 'e4', type: 'file',   value: 'pteranodon.exe' },
        { id: 'e5', type: 'domain', value: 'c2.duckdns.org' },
      ],
      chain: [
        { entity_id: 'e1', role: 'entry',   techniques: ['IIM-T019'] },
        { entity_id: 'e2', role: 'staging', techniques: ['IIM-T024'] },
        { entity_id: 'e3', role: 'staging', techniques: ['IIM-T021'] },
        { entity_id: 'e4', role: 'payload', techniques: [] },
        { entity_id: 'e5', role: 'c2',      techniques: ['IIM-T008', 'IIM-T011', 'IIM-T013'] },
      ],
      relations: [
        { from: 'e1', to: 'e2', type: 'download', sequence_order: 1 },
        { from: 'e2', to: 'e3', type: 'drops',    sequence_order: 2 },
        { from: 'e3', to: 'e4', type: 'execute',  sequence_order: 3 },
        { from: 'e4', to: 'e5', type: 'connect',  sequence_order: 4 },
      ],
    },
  },
  {
    name: 'Malvertising via TDS',
    tag: 'chain · generic',
    data: {
      iim_version: '1.1', chain_id: 'malvertising-tds-example',
      entities: [
        { id: 'e1', type: 'url',    value: 'https://ad.network/click' },
        { id: 'e2', type: 'url',    value: 'https://shortener.example/abc' },
        { id: 'e3', type: 'domain', value: 'tds.example.net' },
        { id: 'e4', type: 'url',    value: 'https://worker.workers.dev/payload' },
        { id: 'e5', type: 'file',   value: 'loader.exe' },
        { id: 'e6', type: 'domain', value: 'c2.cloudfront.net' },
      ],
      chain: [
        { entity_id: 'e1', role: 'entry',      techniques: [] },
        { entity_id: 'e2', role: 'redirector', techniques: ['IIM-T016'] },
        { entity_id: 'e3', role: 'redirector', techniques: ['IIM-T017', 'IIM-T020'] },
        { entity_id: 'e4', role: 'staging',    techniques: ['IIM-T005'] },
        { entity_id: 'e5', role: 'payload',    techniques: [] },
        { entity_id: 'e6', role: 'c2',         techniques: ['IIM-T001'] },
      ],
      relations: [
        { from: 'e1', to: 'e2', type: 'redirect', sequence_order: 1 },
        { from: 'e2', to: 'e3', type: 'redirect', sequence_order: 2 },
        { from: 'e3', to: 'e4', type: 'redirect', sequence_order: 3 },
        { from: 'e4', to: 'e5', type: 'download', sequence_order: 4 },
        { from: 'e5', to: 'e6', type: 'connect',  sequence_order: 5 },
      ],
    },
  },
  {
    name: 'Pattern · RAR-HTA to DynDNS C2 (MB-F-0023)',
    tag: 'pattern · structural',
    data: {
      pattern_id: 'MB-F-0023', name: 'RAR-HTA Delivery to DynDNS C2',
      iim_version: '1.1', match_semantics: 'structural',
      shape: [
        { role: 'entry',   techniques: ['IIM-T019'] },
        { role: 'staging', techniques: ['IIM-T024'] },
        { role: 'staging', techniques: ['IIM-T021'] },
        { role: 'payload', techniques: [] },
        { role: 'c2',      techniques: ['IIM-T008', 'IIM-T011'] },
      ],
      relations: [
        { from_position: 0, to_position: 1, type: 'download' },
        { from_position: 1, to_position: 2, type: 'drops' },
        { from_position: 2, to_position: 3, type: 'execute' },
        { from_position: 3, to_position: 4, type: 'connect' },
      ],
    },
  },
  {
    name: 'Dead-Drop Resolver Flow',
    tag: 'chain · small',
    data: {
      iim_version: '1.1', chain_id: 'dead-drop-example',
      entities: [
        { id: 'e1', type: 'file',   value: 'implant.exe' },
        { id: 'e2', type: 'url',    value: 'https://t.me/channel/latest' },
        { id: 'e3', type: 'domain', value: 'real-c2.duckdns.org' },
      ],
      chain: [
        { entity_id: 'e1', role: 'payload', techniques: [] },
        { entity_id: 'e2', role: 'c2',      techniques: ['IIM-T013', 'IIM-T006'] },
        { entity_id: 'e3', role: 'c2',      techniques: ['IIM-T008', 'IIM-T011'] },
      ],
      relations: [
        { from: 'e1', to: 'e2', type: 'references', sequence_order: 1 },
        { from: 'e2', to: 'e3', type: 'resolves-to', sequence_order: 2 },
        { from: 'e1', to: 'e3', type: 'connect',    sequence_order: 3 },
      ],
    },
  },
];

function vizRenderExampleList() {
  const el = document.getElementById('example-list');
  el.innerHTML = VIZ_EXAMPLES.map((e, i) => `
    <div class="example-item" onclick="vizLoadExample(${i})">
      <div class="ex-name">${escapeHtml(e.name)}</div>
      <div class="ex-meta"><span>${escapeHtml(e.tag)}</span></div>
    </div>
  `).join('');
}

function vizLoadExample(idx) {
  const ex = VIZ_EXAMPLES[idx];
  if (!ex) return;
  document.getElementById('viz-input').value = JSON.stringify(ex.data, null, 2);
  vizParseInput();
}

function vizFromBuilder() {
  const chain = buildChainJson();
  if (!state.entities.length) {
    toast('Chain Builder is empty - add entities first', 'error');
    return;
  }
  document.getElementById('viz-input').value = JSON.stringify(chain, null, 2);
  vizParseInput();
}

function vizParseInput() {
  const txt = document.getElementById('viz-input').value.trim();
  if (!txt) { toast('No input', 'error'); return; }
  let parsed;
  try { parsed = JSON.parse(txt); }
  catch (e) { toast('Invalid JSON: ' + e.message, 'error'); return; }
  vizLoadData(parsed);
}

function vizLoadData(data) {
  // Detect type
  const isPattern = data.pattern_id !== undefined && Array.isArray(data.shape);
  const isChain = Array.isArray(data.entities) && Array.isArray(data.chain);
  if (!isPattern && !isChain) {
    toast('Input is neither a valid chain nor pattern', 'error');
    return;
  }

  vizState.isPattern = isPattern;

  if (isPattern) {
    // Normalize pattern to unified shape
    vizState.data = {
      title: data.name || data.pattern_id || 'Pattern',
      subtitle: data.pattern_id,
      kind: 'pattern',
      positions: data.shape.map((s, i) => ({
        idx: i,
        role: s.role,
        techniques: s.techniques || [],
        entity: null, // patterns are abstract
        label: s.role,
        type: null,
      })),
      relations: (data.relations || []).map(r => ({
        fromIdx: r.from_position,
        toIdx: r.to_position,
        type: r.type,
        seq: null,
      })),
    };
  } else {
    // Normalize chain
    const entMap = {};
    for (const e of (data.entities || [])) entMap[e.id] = e;
    vizState.data = {
      title: data.chain_id || 'Chain',
      subtitle: 'IIM v' + (data.iim_version || '?'),
      kind: 'chain',
      positions: (data.chain || []).map((p, i) => {
        const ent = entMap[p.entity_id] || {};
        return {
          idx: i,
          role: p.role,
          techniques: p.techniques || [],
          entity: ent,
          label: ent.value || p.entity_id || '?',
          type: ent.type || null,
        };
      }),
      relations: (data.relations || []).map(r => ({
        fromIdx: Object.values(data.chain || []).findIndex(p => p.entity_id === r.from),
        toIdx: Object.values(data.chain || []).findIndex(p => p.entity_id === r.to),
        type: r.type,
        seq: r.sequence_order,
      })).filter(r => r.fromIdx >= 0 && r.toIdx >= 0),
    };
  }

  // Update stats
  const uniqTechs = new Set();
  vizState.data.positions.forEach(p => p.techniques.forEach(t => uniqTechs.add(t)));
  document.getElementById('viz-stat-pos').textContent = vizState.data.positions.length;
  document.getElementById('viz-stat-rel').textContent = vizState.data.relations.length;
  document.getElementById('viz-stat-tech').textContent = uniqTechs.size;

  document.getElementById('viz-empty').style.display = 'none';
  document.getElementById('viz-legend').style.display = 'flex';
  vizReset();
  vizRender();
}

function vizSetMode(mode) {
  vizState.mode = mode;
  document.getElementById('viz-mode-flow').classList.toggle('active', mode === 'flow');
  document.getElementById('viz-mode-graph').classList.toggle('active', mode === 'graph');
  if (vizState.data) { vizReset(); vizRender(); }
}

function vizReset() {
  vizState.pan = { x: 0, y: 0 };
  vizState.zoom = 1;
}

function vizZoom(factor) {
  vizState.zoom *= factor;
  vizState.zoom = Math.max(0.3, Math.min(4, vizState.zoom));
  vizApplyTransform();
}

function vizFit() {
  if (!vizState.data) return;
  vizReset();
  vizRender();
}

function vizApplyTransform() {
  const g = document.getElementById('viz-root');
  if (!g) return;
  g.setAttribute('transform', `translate(${vizState.pan.x},${vizState.pan.y}) scale(${vizState.zoom})`);
}

// -------------------- LAYOUT: FLOW (horizontal) --------------------
function vizLayoutFlow(data) {
  const NW = 220, NH = 120, GAP_X = 90;
  const positions = data.positions.map((p, i) => ({
    ...p,
    x: i * (NW + GAP_X),
    y: 0,
    w: NW,
    h: NH,
  }));
  return { positions, width: positions.length * (NW + GAP_X), height: 200 };
}

// -------------------- LAYOUT: GRAPH (force-lite) --------------------
function vizLayoutGraph(data) {
  const NW = 200, NH = 110;
  const N = data.positions.length;
  if (N === 0) return { positions: [], width: 800, height: 500 };

  // Start with a circular layout then relax with a tiny force-lite pass
  const R = Math.max(220, N * 50);
  let pts = data.positions.map((p, i) => {
    const ang = (i / N) * Math.PI * 2 - Math.PI / 2;
    return { ...p, x: Math.cos(ang) * R, y: Math.sin(ang) * R, w: NW, h: NH };
  });

  // Build adjacency for pull
  const adj = {};
  for (const r of data.relations) {
    (adj[r.fromIdx] = adj[r.fromIdx] || []).push(r.toIdx);
    (adj[r.toIdx]   = adj[r.toIdx]   || []).push(r.fromIdx);
  }

  // Run a few relaxation iterations
  for (let iter = 0; iter < 80; iter++) {
    const forces = pts.map(() => ({ x: 0, y: 0 }));
    // Repulsion
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
      const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
      const d2 = Math.max(100, dx*dx + dy*dy);
      const f = 80000 / d2;
      const d = Math.sqrt(d2);
      const fx = (dx / d) * f, fy = (dy / d) * f;
      forces[i].x += fx; forces[i].y += fy;
      forces[j].x -= fx; forces[j].y -= fy;
    }
    // Attraction along edges
    for (const r of data.relations) {
      const i = r.fromIdx, j = r.toIdx;
      const dx = pts[j].x - pts[i].x, dy = pts[j].y - pts[i].y;
      const d = Math.sqrt(dx*dx + dy*dy) || 1;
      const ideal = 280;
      const f = (d - ideal) * 0.02;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      forces[i].x += fx; forces[i].y += fy;
      forces[j].x -= fx; forces[j].y -= fy;
    }
    // Center pull
    for (let i = 0; i < N; i++) {
      forces[i].x -= pts[i].x * 0.004;
      forces[i].y -= pts[i].y * 0.004;
    }
    // Apply
    for (let i = 0; i < N; i++) {
      pts[i].x += forces[i].x * 0.05;
      pts[i].y += forces[i].y * 0.05;
    }
  }

  const xs = pts.map(p => p.x), ys = pts.map(p => p.y);
  const minX = Math.min(...xs) - NW, minY = Math.min(...ys) - NH;
  const maxX = Math.max(...xs) + NW, maxY = Math.max(...ys) + NH;

  pts = pts.map(p => ({ ...p, x: p.x - minX, y: p.y - minY }));

  return { positions: pts, width: maxX - minX, height: maxY - minY };
}

// -------------------- RENDER --------------------
function vizRender() {
  if (!vizState.data) return;
  const svg = document.getElementById('viz-svg');
  const wrap = document.getElementById('viz-canvas-wrap');
  const W = wrap.clientWidth, H = wrap.clientHeight;

  const layout = vizState.mode === 'flow'
    ? vizLayoutFlow(vizState.data)
    : vizLayoutGraph(vizState.data);

  // Fit viewBox with padding
  const padding = 80;
  const viewW = layout.width + padding * 2;
  const viewH = Math.max(layout.height + padding * 2, 360);
  svg.setAttribute('viewBox', `${-padding} ${-padding - (vizState.mode === 'flow' ? (viewH - 200)/2 : 0)} ${viewW} ${viewH}`);
  svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

  let html = `
    <defs>
      <marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L0,6 L9,3 z" class="arrow-head" />
      </marker>
      <marker id="arrow-hl" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L0,6 L9,3 z" fill="#6de4ff" />
      </marker>
    </defs>
    <g id="viz-root">
  `;

  // Draw edges first (below nodes)
  for (const r of vizState.data.relations) {
    const from = layout.positions[r.fromIdx];
    const to = layout.positions[r.toIdx];
    if (!from || !to) continue;
    const path = vizEdgePath(from, to, vizState.mode);
    html += `<path class="edge" d="${path.d}" marker-end="url(#arrow)"></path>`;
    // Edge label on midpoint
    html += `<text class="edge-label" x="${path.midX}" y="${path.midY - 6}" text-anchor="middle">${escapeHtml(r.type || '')}</text>`;
    // Sequence badge
    if (r.seq != null) {
      html += `<rect class="seq-badge" x="${path.midX - 12}" y="${path.midY + 2}" width="24" height="14" rx="7"></rect>`;
      html += `<text class="seq-badge-label" x="${path.midX}" y="${path.midY + 12}" text-anchor="middle">${r.seq}</text>`;
    }
  }

  // Draw nodes
  for (const p of layout.positions) {
    html += vizRenderNode(p);
  }

  html += `</g>`;
  svg.innerHTML = html;

  // Attach node handlers
  svg.querySelectorAll('[data-node-idx]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(el.getAttribute('data-node-idx'));
      vizShowPopover(idx, e);
    });
  });

  vizApplyTransform();
  vizAttachPanHandlers(svg);
}

function vizRenderNode(p) {
  const x = p.x, y = p.y, w = p.w, h = p.h;
  const role = p.role || 'unknown';
  let html = `<g data-node-idx="${p.idx}" style="cursor: pointer;">`;
  html += `<rect class="node-body node-${role}" x="${x}" y="${y}" width="${w}" height="${h}"></rect>`;
  // Position index in top-left corner
  html += `<text class="node-pos-idx" x="${x + 10}" y="${y + 16}">POS ${p.idx.toString().padStart(2,'0')}</text>`;
  // Role badge
  html += `<text class="node-role-label ${role}" x="${x + w - 10}" y="${y + 16}" text-anchor="end">${role.toUpperCase()}</text>`;
  // Entity label (chain) or role (pattern)
  const label = p.label || role;
  const displayLabel = label.length > 28 ? label.substring(0, 26) + '…' : label;
  html += `<text class="node-entity-label" x="${x + 10}" y="${y + 40}">${escapeHtml(displayLabel)}</text>`;
  if (p.type) {
    html += `<text class="node-entity-type" x="${x + 10}" y="${y + 54}">${escapeHtml(p.type.toUpperCase())}</text>`;
  }
  // Technique chips (up to 4, then +N)
  const chips = p.techniques.slice(0, 4);
  const overflow = p.techniques.length - chips.length;
  let chipY = y + h - 28;
  let chipX = x + 10;
  for (const t of chips) {
    const cw = 44;
    html += `<rect class="tech-chip-bg" x="${chipX}" y="${chipY}" width="${cw}" height="12" rx="2"></rect>`;
    html += `<text class="tech-chip-label" x="${chipX + cw/2}" y="${chipY + 9}" text-anchor="middle">${t.replace('IIM-', '')}</text>`;
    chipX += cw + 4;
    if (chipX + cw > x + w - 10) { chipX = x + 10; chipY += 14; }
  }
  if (overflow > 0) {
    html += `<text class="tech-chip-label" x="${chipX}" y="${chipY + 9}">+${overflow}</text>`;
  }
  html += `</g>`;
  return html;
}

function vizEdgePath(from, to, mode) {
  // Compute edge path from node edges (not centers)
  const fcx = from.x + from.w/2, fcy = from.y + from.h/2;
  const tcx = to.x + to.w/2, tcy = to.y + to.h/2;

  if (mode === 'flow') {
    // Straight horizontal arrow between right edge and left edge
    const sx = from.x + from.w, sy = fcy;
    const ex = to.x, ey = tcy;
    const midX = (sx + ex) / 2, midY = (sy + ey) / 2;
    return { d: `M ${sx} ${sy} L ${ex} ${ey}`, midX, midY };
  } else {
    // Graph mode: line from center to center, clipped at node boundary
    const dx = tcx - fcx, dy = tcy - fcy;
    const ang = Math.atan2(dy, dx);
    // Exit point from source node
    const exitX = fcx + Math.cos(ang) * (from.w / 2 + 6);
    const exitY = fcy + Math.sin(ang) * (from.h / 2 + 6);
    const entryX = tcx - Math.cos(ang) * (to.w / 2 + 6);
    const entryY = tcy - Math.sin(ang) * (to.h / 2 + 6);
    // Gentle curve
    const midX = (exitX + entryX) / 2, midY = (exitY + entryY) / 2;
    const cx = midX - dy * 0.08, cy = midY + dx * 0.08;
    return { d: `M ${exitX} ${exitY} Q ${cx} ${cy} ${entryX} ${entryY}`, midX: cx, midY: cy };
  }
}

function vizAttachPanHandlers(svg) {
  svg.onmousedown = (e) => {
    if (e.target !== svg && !e.target.classList.contains('viz-svg')) return;
    vizClosePopover();
    vizState.dragging = true;
    vizState.dragStart = { x: e.clientX - vizState.pan.x, y: e.clientY - vizState.pan.y };
  };
  svg.onmousemove = (e) => {
    if (!vizState.dragging) return;
    vizState.pan.x = e.clientX - vizState.dragStart.x;
    vizState.pan.y = e.clientY - vizState.dragStart.y;
    vizApplyTransform();
  };
  svg.onmouseup = svg.onmouseleave = () => { vizState.dragging = false; };
  svg.onwheel = (e) => {
    e.preventDefault();
    vizZoom(e.deltaY < 0 ? 1.1 : 0.909);
  };
}

function vizShowPopover(idx, evt) {
  const p = vizState.data.positions[idx];
  if (!p) return;
  const pop = document.getElementById('viz-popover');
  const content = document.getElementById('viz-popover-content');
  let html = `<h5 style="color: var(--role-${p.role});">${p.role.toUpperCase()} · Position ${p.idx}</h5>`;
  if (p.entity) {
    html += `<div class="pop-kv"><span class="k">Entity</span><span class="v">${escapeHtml(p.entity.id || '?')}</span></div>`;
    html += `<div class="pop-kv"><span class="k">Type</span><span class="v">${escapeHtml(p.entity.type || '?')}</span></div>`;
    html += `<div class="pop-kv"><span class="k">Value</span><span class="v">${escapeHtml(p.entity.value || '?')}</span></div>`;
  }
  if (p.techniques && p.techniques.length) {
    html += `<div class="pop-kv"><span class="k">Techniques</span><span class="v">`;
    html += p.techniques.map(t => `<span class="chip" style="margin: 2px 2px 0 0;">${t}</span>`).join('');
    html += `</span></div>`;
  } else {
    html += `<div class="pop-kv"><span class="k">Techniques</span><span class="v" style="color: var(--bone-darker);">none</span></div>`;
  }
  content.innerHTML = html;

  // Position popover near click, clamped to viewport
  const wrap = document.getElementById('viz-canvas-wrap').getBoundingClientRect();
  let px = evt.clientX - wrap.left + 12;
  let py = evt.clientY - wrap.top + 12;
  if (px + 340 > wrap.width) px = wrap.width - 340;
  if (py + 200 > wrap.height) py = wrap.height - 200;
  pop.style.left = px + 'px';
  pop.style.top = py + 'px';
  pop.classList.add('show');
}

function vizClosePopover() {
  document.getElementById('viz-popover').classList.remove('show');
}

function vizExportSvg() {
  const svg = document.getElementById('viz-svg');
  if (!vizState.data) { toast('Nothing to export', 'error'); return; }
  // Inline styles for portability
  const style = `
    .node-body { stroke-width: 1.5; rx: 4; }
    .node-entry      { fill: #101c2c; stroke: #8ec7ff; }
    .node-redirector { fill: #141a30; stroke: #b39dff; }
    .node-staging    { fill: #0c1e1a; stroke: #3ad0a8; }
    .node-payload    { fill: #241210; stroke: #ff7a5c; }
    .node-c2         { fill: #2a1e0d; stroke: #ffb454; }
    text { font-family: var(--font-mono); fill: #e8ecf2; }
    .node-role-label { font-size: 9px; letter-spacing: 0.15em; }
    .node-role-label.entry      { fill: #8ec7ff; }
    .node-role-label.redirector { fill: #b39dff; }
    .node-role-label.staging    { fill: #3ad0a8; }
    .node-role-label.payload    { fill: #ff7a5c; }
    .node-role-label.c2         { fill: #ffb454; }
    .node-entity-label { font-size: 11px; fill: #e8ecf2; }
    .node-entity-type { font-size: 9px; fill: #5a6a82; }
    .node-pos-idx { font-size: 9px; fill: #5a6a82; font-family: var(--font-serif); }
    .tech-chip-bg { fill: rgba(58, 208, 168, 0.12); stroke: rgba(58, 208, 168, 0.4); stroke-width: 0.5; }
    .tech-chip-label { font-size: 8px; fill: #3ad0a8; }
    .edge { fill: none; stroke: #5a6a82; stroke-width: 1.2; opacity: 0.7; }
    .edge-label { font-size: 9px; fill: #5a6a82; }
    .arrow-head { fill: #5a6a82; }
    .seq-badge { fill: #030812; stroke: #3ad0a8; stroke-width: 1; }
    .seq-badge-label { font-size: 9px; fill: #3ad0a8; font-family: var(--font-serif); }
  `;
  const clone = svg.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  // Inject style
  const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
  styleEl.textContent = style;
  clone.insertBefore(styleEl, clone.firstChild);
  // Wrap in full SVG with background
  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  const vb = clone.getAttribute('viewBox').split(' ').map(Number);
  bg.setAttribute('x', vb[0]);
  bg.setAttribute('y', vb[1]);
  bg.setAttribute('width', vb[2]);
  bg.setAttribute('height', vb[3]);
  bg.setAttribute('fill', '#030812');
  clone.insertBefore(bg, styleEl.nextSibling);
  const xml = new XMLSerializer().serializeToString(clone);
  const name = (vizState.data.title || 'iim-viz').replace(/[^a-z0-9]/gi, '_');
  downloadFile(xml, `${name}.svg`, 'image/svg+xml');
  toast('SVG downloaded');
}

async function vizExportPng() {
  const svg = document.getElementById('viz-svg');
  if (!vizState.data) { toast('Nothing to export', 'error'); return; }
  // Build a fully-styled SVG string (reuse export logic)
  const svgEl = document.getElementById('viz-svg');
  const rect = svgEl.getBoundingClientRect();
  const w = Math.max(1200, rect.width * 2);
  const h = Math.max(700, rect.height * 2);
  // Create a canvas and draw the SVG
  const xml = (() => {
    const clone = svgEl.cloneNode(true);
    const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    styleEl.textContent = `
      .node-entry { fill: #101c2c; stroke: #8ec7ff; stroke-width: 1.5; }
      .node-redirector { fill: #141a30; stroke: #b39dff; stroke-width: 1.5; }
      .node-staging { fill: #0c1e1a; stroke: #3ad0a8; stroke-width: 1.5; }
      .node-payload { fill: #241210; stroke: #ff7a5c; stroke-width: 1.5; }
      .node-c2 { fill: #2a1e0d; stroke: #ffb454; stroke-width: 1.5; }
      text { font-family: var(--font-mono); fill: #e8ecf2; }
      .node-role-label.entry { fill: #8ec7ff; font-size: 9px; }
      .node-role-label.redirector { fill: #b39dff; font-size: 9px; }
      .node-role-label.staging { fill: #3ad0a8; font-size: 9px; }
      .node-role-label.payload { fill: #ff7a5c; font-size: 9px; }
      .node-role-label.c2 { fill: #ffb454; font-size: 9px; }
      .node-entity-label { font-size: 11px; }
      .node-entity-type { font-size: 9px; fill: #5a6a82; }
      .node-pos-idx { font-size: 9px; fill: #5a6a82; }
      .tech-chip-bg { fill: rgba(58, 208, 168, 0.12); stroke: rgba(58, 208, 168, 0.4); }
      .tech-chip-label { font-size: 8px; fill: #3ad0a8; }
      .edge { fill: none; stroke: #5a6a82; stroke-width: 1.2; opacity: 0.7; }
      .edge-label { font-size: 9px; fill: #5a6a82; }
      .arrow-head { fill: #5a6a82; }
      .seq-badge { fill: #030812; stroke: #3ad0a8; }
      .seq-badge-label { font-size: 9px; fill: #3ad0a8; }
    `;
    clone.insertBefore(styleEl, clone.firstChild);
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    const vb = clone.getAttribute('viewBox').split(' ').map(Number);
    bg.setAttribute('x', vb[0]);
    bg.setAttribute('y', vb[1]);
    bg.setAttribute('width', vb[2]);
    bg.setAttribute('height', vb[3]);
    bg.setAttribute('fill', '#030812');
    clone.insertBefore(bg, styleEl.nextSibling);
    clone.setAttribute('width', w);
    clone.setAttribute('height', h);
    return new XMLSerializer().serializeToString(clone);
  })();
  const img = new Image();
  const svgBlob = new Blob([xml], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(svgBlob);
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#030812';
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    URL.revokeObjectURL(url);
    canvas.toBlob((blob) => {
      const name = (vizState.data.title || 'iim-viz').replace(/[^a-z0-9]/gi, '_');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${name}.png`;
      document.body.appendChild(a); a.click(); a.remove();
      toast('PNG downloaded');
    }, 'image/png');
  };
  img.onerror = () => { toast('PNG export failed', 'error'); URL.revokeObjectURL(url); };
  img.src = url;
}

// Re-render on window resize for graph layout
window.addEventListener('resize', () => { if (vizState.data) vizRender(); });

// =========================================================================
// INTEROP (STIX ↔ IIM)
// =========================================================================
const interopState = {
  direction: 'export',  // 'export' (IIM->STIX) or 'import' (STIX->IIM)
  lastOutput: null,
  lastOutputKind: null, // 'bundle' | 'chain'
};

function interopSetDir(dir) {
  interopState.direction = dir;
  document.getElementById('interop-dir-export').classList.toggle('primary', dir === 'export');
  document.getElementById('interop-dir-import').classList.toggle('primary', dir === 'import');
  document.getElementById('interop-input-title').textContent =
    dir === 'export' ? 'IIM Chain (input)' : 'STIX 2.1 Bundle (input)';
  document.getElementById('interop-output-title').textContent =
    dir === 'export' ? 'STIX 2.1 Bundle (output)' : 'IIM Chain (output)';
  document.getElementById('interop-from-builder').style.display =
    dir === 'export' ? '' : 'none';
  document.getElementById('interop-dir-desc').innerHTML = dir === 'export'
    ? 'Convert an IIM chain to a STIX 2.1 bundle. <b style="color: var(--plankton);">Lossless</b> - custom properties preserve every IIM concept.'
    : 'Convert a STIX 2.1 bundle to an IIM chain. <b style="color: var(--amber);">Heuristic</b> - roles and techniques are inferred and marked for review.';
  interopClearOutput();
}

function interopFromBuilder() {
  if (interopState.direction !== 'export') return;
  const chain = buildChainJson();
  if (!state.entities.length) {
    toast('Chain Builder is empty - add entities first', 'error');
    return;
  }
  document.getElementById('interop-input').value = JSON.stringify(chain, null, 2);
  toast('Loaded from Chain Builder');
}

function interopLoadExample() {
  if (interopState.direction === 'export') {
    // Load an IIM chain example
    document.getElementById('interop-input').value = JSON.stringify({
      iim_version: '1.1',
      chain_id: 'gamaredon-example',
      actor_id: 'MB-0001',
      confidence: 'confirmed',
      entities: [
        { id: 'e1', type: 'url',    value: 'https://phish.example/lure.pdf' },
        { id: 'e2', type: 'file',   value: 'loader.hta' },
        { id: 'e3', type: 'domain', value: 'c2.duckdns.org' },
      ],
      chain: [
        { entity_id: 'e1', role: 'entry',   techniques: ['IIM-T019'] },
        { entity_id: 'e2', role: 'staging', techniques: ['IIM-T021'] },
        { entity_id: 'e3', role: 'c2',      techniques: ['IIM-T008', 'IIM-T011'] },
      ],
      relations: [
        { from: 'e1', to: 'e2', type: 'download', sequence_order: 1 },
        { from: 'e2', to: 'e3', type: 'connect',  sequence_order: 2 },
      ],
    }, null, 2);
  } else {
    // Load a naive STIX bundle example
    document.getElementById('interop-input').value = JSON.stringify({
      type: 'bundle',
      id: 'bundle--11111111-2222-3333-4444-555555555555',
      objects: [
        {
          type: 'indicator', spec_version: '2.1',
          id: 'indicator--aaaa0001-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          pattern: "[url:value = 'https://evil.example/landing']",
          pattern_type: 'stix', valid_from: '2026-01-15T10:00:00.000Z',
          indicator_types: ['malicious-activity']
        },
        {
          type: 'indicator', spec_version: '2.1',
          id: 'indicator--bbbb0002-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          pattern: "[domain-name:value = 'foreign-c2.duckdns.org']",
          pattern_type: 'stix', valid_from: '2026-01-15T10:00:00.000Z',
          indicator_types: ['malicious-activity']
        },
        {
          type: 'infrastructure', spec_version: '2.1',
          id: 'infrastructure--aaaa0003-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          name: 'Phishing entry', infrastructure_types: ['phishing']
        },
        {
          type: 'infrastructure', spec_version: '2.1',
          id: 'infrastructure--bbbb0004-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          name: 'C2 endpoint', infrastructure_types: ['command-and-control']
        },
        {
          type: 'relationship', spec_version: '2.1',
          id: 'relationship--cccc0005-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          relationship_type: 'indicates',
          source_ref: 'indicator--aaaa0001-0000-0000-0000-000000000000',
          target_ref: 'infrastructure--aaaa0003-0000-0000-0000-000000000000'
        },
        {
          type: 'relationship', spec_version: '2.1',
          id: 'relationship--dddd0006-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          relationship_type: 'indicates',
          source_ref: 'indicator--bbbb0002-0000-0000-0000-000000000000',
          target_ref: 'infrastructure--bbbb0004-0000-0000-0000-000000000000'
        },
        {
          type: 'relationship', spec_version: '2.1',
          id: 'relationship--eeee0007-0000-0000-0000-000000000000',
          created: '2026-01-15T10:00:00.000Z', modified: '2026-01-15T10:00:00.000Z',
          relationship_type: 'communicates-with',
          source_ref: 'infrastructure--aaaa0003-0000-0000-0000-000000000000',
          target_ref: 'infrastructure--bbbb0004-0000-0000-0000-000000000000'
        },
      ]
    }, null, 2);
  }
  toast('Example loaded');
}

function interopClearOutput() {
  document.getElementById('interop-output').innerHTML = '// Output will appear here after conversion';
  document.getElementById('interop-report-card').style.display = 'none';
  document.getElementById('interop-report').innerHTML = '';
  interopState.lastOutput = null;
  interopState.lastOutputKind = null;
}

async function interopRun() {
  const txt = document.getElementById('interop-input').value.trim();
  if (!txt) { toast('Input is empty', 'error'); return; }
  let parsed;
  try { parsed = JSON.parse(txt); }
  catch (e) { toast('Invalid JSON: ' + e.message, 'error'); return; }

  if (interopState.direction === 'export') {
    // IIM -> STIX
    try {
      const res = await fetch('/api/export/stix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      const data = await res.json();
      if (data.error) {
        toast('Export failed: ' + data.error, 'error');
        if (data.validation) {
          renderValidation(data.validation, 'interop-report');
          document.getElementById('interop-report-card').style.display = '';
        }
        return;
      }
      const jsonStr = JSON.stringify(data, null, 2);
      document.getElementById('interop-output').innerHTML = syntaxHighlight(jsonStr);
      interopState.lastOutput = data;
      interopState.lastOutputKind = 'bundle';
      toast(`Converted -> ${data.objects.length} STIX objects`);
    } catch (e) {
      toast('Network error: ' + e.message, 'error');
    }
  } else {
    // STIX -> IIM
    try {
      const res = await fetch('/api/import/stix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bundle: parsed }),
      });
      const data = await res.json();
      if (data.error) {
        toast('Import failed: ' + data.error, 'error');
        return;
      }
      const jsonStr = JSON.stringify(data.chain, null, 2);
      document.getElementById('interop-output').innerHTML = syntaxHighlight(jsonStr);
      interopState.lastOutput = data.chain;
      interopState.lastOutputKind = 'chain';
      // Render the import report
      renderImportReport(data.report, data.validation);
      document.getElementById('interop-report-card').style.display = '';
      toast(`Imported -> ${data.chain.chain.length} positions, ${data.report.positions_needing_review} need review`);
    } catch (e) {
      toast('Network error: ' + e.message, 'error');
    }
  }
}

function renderImportReport(report, validation) {
  const el = document.getElementById('interop-report');
  const rt = report.round_trip_detected;
  let html = `
    <div style="margin-bottom: 14px; padding: 10px 14px; background: ${rt ? 'rgba(58, 208, 168, 0.05)' : 'rgba(255, 180, 84, 0.05)'}; border-left: 2px solid ${rt ? 'var(--plankton)' : 'var(--amber)'}; font-size: 11px;">
      <b style="color: ${rt ? 'var(--plankton)' : 'var(--amber)'};">${rt ? '✓ Round-trip detected' : '⚠ Heuristic import'}</b>
      <div style="color: var(--bone-dim); margin-top: 4px; line-height: 1.6;">
        ${rt
          ? 'The source bundle carried IIM metadata (x_iim_* properties). Full fidelity conversion.'
          : 'The source bundle had no IIM metadata. Roles and techniques were inferred; analyst review required.'}
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 11px; margin-bottom: 14px;">
      <div>
        <div style="font-size: 9px; letter-spacing: 0.2em; color: var(--bone-darker); margin-bottom: 6px;">STIX CONTAINED</div>
        ${Object.entries(report.stix_object_counts || {}).map(([t, n]) =>
          `<div style="display: flex; justify-content: space-between; padding: 2px 0; color: var(--bone-dim);"><span>${t}</span><span style="color: var(--bone);">${n}</span></div>`
        ).join('')}
      </div>
      <div>
        <div style="font-size: 9px; letter-spacing: 0.2em; color: var(--bone-darker); margin-bottom: 6px;">IIM PRODUCED</div>
        <div style="display: flex; justify-content: space-between; padding: 2px 0; color: var(--bone-dim);"><span>entities</span><span style="color: var(--bone);">${report.iim_entity_count}</span></div>
        <div style="display: flex; justify-content: space-between; padding: 2px 0; color: var(--bone-dim);"><span>positions</span><span style="color: var(--bone);">${report.iim_position_count}</span></div>
        <div style="display: flex; justify-content: space-between; padding: 2px 0; color: var(--bone-dim);"><span>relations</span><span style="color: var(--bone);">${report.iim_relation_count}</span></div>
        <div style="display: flex; justify-content: space-between; padding: 2px 0; color: var(--amber);"><span>need review</span><span>${report.positions_needing_review}</span></div>
      </div>
    </div>
  `;
  if (report.warnings && report.warnings.length) {
    html += `
      <div style="padding: 10px 14px; background: rgba(255, 180, 84, 0.05); border-left: 2px solid var(--amber); font-size: 11px;">
        <b style="color: var(--amber);">Warnings (${report.warnings.length})</b>
        <ul style="margin-top: 6px; padding-left: 18px; color: var(--bone-dim); line-height: 1.6;">
          ${report.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
        </ul>
      </div>
    `;
  }
  if (validation && !validation.valid) {
    html += `<div style="margin-top: 12px;">`;
    el.innerHTML = html;
    renderValidation(validation, 'interop-report-valid');
    html += `<div id="interop-report-valid"></div></div>`;
  }
  el.innerHTML = html;
}

function interopCopyOutput() {
  if (!interopState.lastOutput) { toast('Nothing to copy', 'error'); return; }
  navigator.clipboard.writeText(JSON.stringify(interopState.lastOutput, null, 2));
  toast('Copied to clipboard');
}

function interopDownloadOutput() {
  if (!interopState.lastOutput) { toast('Nothing to download', 'error'); return; }
  const kind = interopState.lastOutputKind;
  const name = kind === 'bundle'
    ? `${interopState.lastOutput.id.replace(/^bundle--/, '').substring(0, 12)}-stix.json`
    : `${interopState.lastOutput.chain_id || 'chain'}.json`;
  downloadFile(JSON.stringify(interopState.lastOutput, null, 2), name, 'application/json');
  toast(`Downloaded ${name}`);
}

init();
</script>
</body>
</html>
"""

# CLI

def cli_validate(path: str, catalog_path: str | None) -> int:
    catalog = load_catalog(catalog_path)
    v = Validator(catalog)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {path}: {e}", file=sys.stderr)
        return 2

    is_pattern = "pattern_id" in data and "shape" in data
    result = v.validate_pattern(data) if is_pattern else v.validate_chain(data)

    print(f"{'✓ Valid' if result['valid'] else '✗ Invalid'} ({'pattern' if is_pattern else 'chain'})")
    for e in result["errors"]:
        print(f"  [ERROR] {e['path']}: {e['message']}")
    for w in result["warnings"]:
        print(f"  [WARN]  {w['path']}: {w['message']}")
    return 0 if result["valid"] else 1


def cli_stix(path: str, catalog_path: str | None) -> int:
    catalog = load_catalog(catalog_path)
    v = Validator(catalog)
    try:
        with open(path, "r", encoding="utf-8") as f:
            chain = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {path}: {e}", file=sys.stderr)
        return 2

    result = v.validate_chain(chain)
    if not result["valid"]:
        print("ERROR: chain is invalid, cannot export:", file=sys.stderr)
        for e in result["errors"]:
            print(f"  [ERROR] {e['path']}: {e['message']}", file=sys.stderr)
        return 1

    bundle = (_lib_iim_chain_to_stix(chain, catalog) if _lib_iim_chain_to_stix else chain_to_stix(chain, catalog))
    print(json.dumps(bundle, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="IIM Workbench - local tool for IIM chain/pattern work")
    ap.add_argument("--port", type=int, default=5000, help="HTTP port (default 5000)")
    ap.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    ap.add_argument("--catalog", help="Path to iim-techniques-v1.0.json")
    ap.add_argument("--validate", metavar="FILE", help="Validate a chain/pattern from CLI, then exit")
    ap.add_argument("--stix", metavar="FILE", help="Export a chain to STIX 2.1 (prints to stdout)")
    ap.add_argument("--version", action="version", version=f"IIM Workbench {VERSION}")
    args = ap.parse_args()

    if args.validate:
        return cli_validate(args.validate, args.catalog)
    if args.stix:
        return cli_stix(args.stix, args.catalog)

    app = create_app(args.catalog)
    print(f"\nIIM Workbench {VERSION}")
    print(f"  -> http://{args.host}:{args.port}\n")
    print(f"  CLI:     python {Path(__file__).name} --validate chain.json")
    print(f"  STIX:    python {Path(__file__).name} --stix chain.json > bundle.json")
    print(f"  Catalog: {args.catalog or 'auto-detect'}\n")
    try:
        app.run(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n[workbench] shutdown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
