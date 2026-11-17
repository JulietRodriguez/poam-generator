"""OSCAL 1.1.2 POA&M export, JSON and XML, standard library only.

Each POAM finding becomes:

    risk       the weakness: status, deadline (scheduled completion), and a
               remediation plan whose tasks are the finding's milestones
    finding    the control it affects (only when the control is a NIST 800-53
               ID such as "AC-2" or "SC-28"; Security Hub control IDs like
               "S3.2" are kept as a property instead)
    poam-item  the POA&M line, linking the risk and the finding

Both outputs are checked against NIST's official OSCAL 1.1.2 POA&M schemas
(JSON Schema and XSD) in CI.
"""

from __future__ import annotations

import json
import re
import uuid
import xml.etree.ElementTree as ET  # noqa: S405 (writing XML, not parsing untrusted input)
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import Finding

OSCAL_NS = "http://csrc.nist.gov/ns/oscal/1.0"
OSCAL_VERSION = "1.1.2"
PROP_NS = "https://github.com/JulietRodriguez/poam-generator/ns/oscal"

# POAM status -> OSCAL risk status (OSCAL's allowed values).
_STATUS_MAP = {
    "Open": "open",
    "In Progress": "remediating",
    "Closed": "closed",
    "Risk Accepted": "deviation-approved",
}

_CONTROL_RE = re.compile(r"^([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?$")
_MILESTONE_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s*[:\-–]\s*(.+)$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_iso(date_str: str, end_of_day: bool = False) -> str:
    """'2026-05-01' -> '2026-05-01T00:00:00Z' (or 23:59:59Z for a deadline)."""
    return f"{date_str}T{'23:59:59' if end_of_day else '00:00:00'}Z"


def statement_id(control: str) -> str | None:
    """'AC-2' -> 'ac-2_smt', 'AC-2(4)' -> 'ac-2.4_smt'; None if not an 800-53 ID."""
    m = _CONTROL_RE.match(control.strip())
    if not m:
        return None
    fam, num, enh = m.groups()
    base = f"{fam.lower()}-{int(num)}"
    return f"{base}.{int(enh)}_smt" if enh else f"{base}_smt"


def _clean(text: str) -> str:
    """OSCAL plain-text values can't have line breaks or edge whitespace."""
    return " ".join((text or "").split())


def _props(finding: Finding) -> list[dict]:
    pairs = [
        ("severity", finding.severity),
        ("security-control", finding.security_control),
        ("source", finding.source),
        ("detection-date", finding.detection_date),
        ("scheduled-completion-date", finding.scheduled_completion),
        ("office-org", finding.office_org),
        ("point-of-contact", finding.point_of_contact),
        ("poam-status", finding.status),
    ]
    return [{"name": n, "ns": PROP_NS, "value": _clean(v)} for n, v in pairs if _clean(v)]


def _tasks(finding: Finding) -> list[dict]:
    """Milestones become tasks. A leading 'YYYY-MM-DD:' becomes the task's date;
    otherwise the task spans detection date to scheduled completion."""
    tasks = []
    for m in finding.milestones:
        match = _MILESTONE_DATE_RE.match(m.strip())
        if match:
            timing = {"on-date": {"date": _date_iso(match.group(1))}}
            title = match.group(2)
        else:
            timing = {
                "within-date-range": {
                    "start": _date_iso(finding.detection_date),
                    "end": _date_iso(finding.scheduled_completion, end_of_day=True),
                }
            }
            title = m
        tasks.append(
            {"uuid": str(uuid.uuid4()), "type": "milestone", "title": _clean(title), "timing": timing}
        )
    return tasks


def _build_model(findings: list[Finding]) -> dict:
    risks, oscal_findings, poam_items = [], [], []
    for f in findings:
        risk_uuid = str(uuid.uuid4())
        risk = {
            "uuid": risk_uuid,
            "title": _clean(f.weakness_name),
            "description": f.weakness_description,
            "statement": f.remediation_plan,
            "status": _STATUS_MAP.get(f.status, "open"),
            "deadline": _date_iso(f.scheduled_completion, end_of_day=True),
            "remediations": [
                {
                    "uuid": str(uuid.uuid4()),
                    "lifecycle": "planned",
                    "title": "Remediation Plan",
                    "description": f.remediation_plan,
                    **(
                        {"required-assets": [{"uuid": str(uuid.uuid4()), "description": f.resources_required}]}
                        if _clean(f.resources_required)
                        else {}
                    ),
                    **({"tasks": _tasks(f)} if f.milestones else {}),
                }
            ],
        }
        risks.append(risk)

        item = {
            "uuid": str(uuid.uuid4()),
            "title": _clean(f.weakness_name),
            "description": f.weakness_description,
            "props": _props(f),
            "related-risks": [{"risk-uuid": risk_uuid}],
        }
        smt = statement_id(f.security_control)
        if smt:
            finding_uuid = str(uuid.uuid4())
            oscal_findings.append(
                {
                    "uuid": finding_uuid,
                    "title": _clean(f"{f.security_control} not satisfied: {f.weakness_name}"),
                    "description": f.weakness_description,
                    "target": {
                        "type": "statement-id",
                        "target-id": smt,
                        "status": {"state": "not-satisfied"},
                    },
                    "related-risks": [{"risk-uuid": risk_uuid}],
                }
            )
            item["related-findings"] = [{"finding-uuid": finding_uuid}]
        if _clean(f.comments):
            item["remarks"] = f.comments
        poam_items.append(item)
    return {"risks": risks, "findings": oscal_findings, "poam_items": poam_items}


def _build_oscal_dict(findings: list[Finding]) -> dict:
    model = _build_model(findings)
    root: dict = {
        "uuid": str(uuid.uuid4()),
        "metadata": {
            "title": "POAM Export",
            "last-modified": _now_iso(),
            "version": __version__,
            "oscal-version": OSCAL_VERSION,
        },
        "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122", "id": str(uuid.uuid4())},
    }
    if model["risks"]:
        root["risks"] = model["risks"]
    if model["findings"]:
        root["findings"] = model["findings"]
    root["poam-items"] = model["poam_items"]
    return {"plan-of-action-and-milestones": root}


def write_oscal_json(findings: list[Finding], output_path: str | Path) -> None:
    doc = _build_oscal_dict(findings)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# XML export. Element order follows the OSCAL 1.1.2 POA&M XSD, and
# multi-line fields (description, statement, remarks) are wrapped in <p>.
# ---------------------------------------------------------------------------


def _sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    el = ET.SubElement(parent, f"{{{OSCAL_NS}}}{tag}")
    if text is not None:
        el.text = text
    return el


def _markup(parent: ET.Element, tag: str, text: str) -> ET.Element:
    el = _sub(parent, tag)
    paragraphs = [p.strip() for p in (text or "").split("\n\n") if p.strip()] or ["-"]
    for p in paragraphs:
        _sub(el, "p", p)
    return el


def _xml_props(parent: ET.Element, props: list[dict]) -> None:
    for p in props:
        el = _sub(parent, "prop")
        el.set("name", p["name"])
        if "ns" in p:
            el.set("ns", p["ns"])
        el.set("value", p["value"])


def _build_oscal_xml(findings: list[Finding]) -> ET.Element:
    doc = _build_oscal_dict(findings)["plan-of-action-and-milestones"]
    ET.register_namespace("", OSCAL_NS)
    root = ET.Element(f"{{{OSCAL_NS}}}plan-of-action-and-milestones")
    root.set("uuid", doc["uuid"])

    meta = _sub(root, "metadata")
    for key in ("title", "last-modified", "version", "oscal-version"):
        _sub(meta, key, doc["metadata"][key])

    sys_id = _sub(root, "system-id", doc["system-id"]["id"])
    sys_id.set("identifier-type", doc["system-id"]["identifier-type"])

    for r in doc.get("risks", []):
        risk = _sub(root, "risk")
        risk.set("uuid", r["uuid"])
        _sub(risk, "title", r["title"])
        _markup(risk, "description", r["description"])
        _markup(risk, "statement", r["statement"])
        _sub(risk, "status", r["status"])
        _sub(risk, "deadline", r["deadline"])
        for rem in r["remediations"]:
            resp = _sub(risk, "response")
            resp.set("uuid", rem["uuid"])
            resp.set("lifecycle", rem["lifecycle"])
            _sub(resp, "title", rem["title"])
            _markup(resp, "description", rem["description"])
            for asset in rem.get("required-assets", []):
                ra = _sub(resp, "required-asset")
                ra.set("uuid", asset["uuid"])
                _markup(ra, "description", asset["description"])
            for t in rem.get("tasks", []):
                task = _sub(resp, "task")
                task.set("uuid", t["uuid"])
                task.set("type", t["type"])
                _sub(task, "title", t["title"])
                timing = _sub(task, "timing")
                if "on-date" in t["timing"]:
                    _sub(timing, "on-date").set("date", t["timing"]["on-date"]["date"])
                else:
                    wdr = _sub(timing, "within-date-range")
                    wdr.set("start", t["timing"]["within-date-range"]["start"])
                    wdr.set("end", t["timing"]["within-date-range"]["end"])

    for f in doc.get("findings", []):
        fe = _sub(root, "finding")
        fe.set("uuid", f["uuid"])
        _sub(fe, "title", f["title"])
        _markup(fe, "description", f["description"])
        target = _sub(fe, "target")
        target.set("type", f["target"]["type"])
        target.set("target-id", f["target"]["target-id"])
        _sub(target, "status").set("state", f["target"]["status"]["state"])
        for rr in f["related-risks"]:
            _sub(fe, "associated-risk").set("risk-uuid", rr["risk-uuid"])

    for p in doc["poam-items"]:
        item = _sub(root, "poam-item")
        item.set("uuid", p["uuid"])
        _sub(item, "title", p["title"])
        _markup(item, "description", p["description"])
        _xml_props(item, p["props"])
        for rf in p.get("related-findings", []):
            _sub(item, "related-finding").set("finding-uuid", rf["finding-uuid"])
        for rr in p["related-risks"]:
            _sub(item, "associated-risk").set("risk-uuid", rr["risk-uuid"])
        if "remarks" in p:
            _markup(item, "remarks", p["remarks"])
    return root


def write_oscal_xml(findings: list[Finding], output_path: str | Path) -> None:
    root = _build_oscal_xml(findings)
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    with open(output_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)
