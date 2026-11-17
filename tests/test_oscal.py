import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from poam_generator.aws_sync import MOCK_FINDINGS
from poam_generator.demo_data import DEMO_FINDINGS
from poam_generator.models import Finding
from poam_generator.oscal import (
    OSCAL_NS,
    OSCAL_VERSION,
    _build_oscal_dict,
    statement_id,
    write_oscal_json,
    write_oscal_xml,
)

ROOT = Path(__file__).resolve().parent.parent
NS = {"o": OSCAL_NS}


@pytest.mark.parametrize(
    ("control", "expected"),
    [("AC-2", "ac-2_smt"), ("AC-2(4)", "ac-2.4_smt"), ("sc-28", "sc-28_smt"), ("S3.2", None), ("", None)],
)
def test_statement_id(control, expected):
    assert statement_id(control) == expected


def test_json_structure(sample_findings):
    root = _build_oscal_dict(sample_findings)["plan-of-action-and-milestones"]
    assert root["metadata"]["oscal-version"] == OSCAL_VERSION == "1.1.2"
    n = len(sample_findings)
    assert len(root["poam-items"]) == len(root["risks"]) == n
    risk_ids = {r["uuid"] for r in root["risks"]}
    finding_ids = {f["uuid"] for f in root.get("findings", [])}
    for item in root["poam-items"]:
        assert {r["risk-uuid"] for r in item["related-risks"]} <= risk_ids
        assert {f["finding-uuid"] for f in item.get("related-findings", [])} <= finding_ids
        assert all(p["value"] and "\n" not in p["value"] for p in item["props"])


def test_status_mapping_and_deadline(valid_dict):
    statuses = {}
    for status in ("Open", "In Progress", "Closed", "Risk Accepted"):
        valid_dict["status"] = status
        risk = _build_oscal_dict([Finding.from_dict(valid_dict)])["plan-of-action-and-milestones"]["risks"][0]
        statuses[status] = risk["status"]
        assert risk["deadline"] == "2026-03-01T23:59:59Z"
    assert statuses == {
        "Open": "open",
        "In Progress": "remediating",
        "Closed": "closed",
        "Risk Accepted": "deviation-approved",
    }


def test_milestone_dates_become_task_dates(valid_dict):
    risk = _build_oscal_dict([Finding.from_dict(valid_dict)])["plan-of-action-and-milestones"]["risks"][0]
    tasks = risk["remediations"][0]["tasks"]
    assert tasks[0]["title"] == "Step one"
    assert tasks[0]["timing"] == {"on-date": {"date": "2026-02-01T00:00:00Z"}}
    assert tasks[1]["timing"]["within-date-range"] == {
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-03-01T23:59:59Z",
    }


def test_non_nist_controls_become_props_not_findings(valid_dict):
    valid_dict["security_control"] = "S3.2"
    root = _build_oscal_dict([Finding.from_dict(valid_dict)])["plan-of-action-and-milestones"]
    assert "findings" not in root
    assert "related-findings" not in root["poam-items"][0]
    props = {p["name"]: p["value"] for p in root["poam-items"][0]["props"]}
    assert props["security-control"] == "S3.2"


def test_empty_optional_values_are_dropped(valid_dict):
    valid_dict.update(point_of_contact="", resources_required="", comments="", milestones=[])
    root = _build_oscal_dict([Finding.from_dict(valid_dict)])["plan-of-action-and-milestones"]
    item, risk = root["poam-items"][0], root["risks"][0]
    assert "point-of-contact" not in {p["name"] for p in item["props"]}
    assert "remarks" not in item
    assert "tasks" not in risk["remediations"][0]
    assert "required-assets" not in risk["remediations"][0]


def test_write_json_and_xml(sample_findings, tmp_path):
    js = tmp_path / "p.json"
    xml = tmp_path / "p.xml"
    write_oscal_json(sample_findings, js)
    write_oscal_xml(sample_findings, xml)
    assert json.loads(js.read_text())["plan-of-action-and-milestones"]["poam-items"]
    root = ET.parse(xml).getroot()
    assert root.tag == f"{{{OSCAL_NS}}}plan-of-action-and-milestones"
    assert len(root.findall("o:poam-item", NS)) == len(sample_findings)
    # multi-line fields are wrapped in <p> as the XML schema requires
    assert root.find("o:risk/o:description/o:p", NS) is not None


# ---------- official NIST schemas (downloaded in CI) ----------

SCHEMA_DIR = Path(os.environ.get("OSCAL_SCHEMA_DIR", ROOT / "schemas"))
JSON_SCHEMA = SCHEMA_DIR / "oscal_poam_schema.json"
XSD = SCHEMA_DIR / "oscal_poam_schema.xsd"
DATASETS = {"demo": DEMO_FINDINGS, "mock-security-hub": MOCK_FINDINGS}


@pytest.mark.skipif(not JSON_SCHEMA.is_file(), reason="OSCAL JSON schema not downloaded")
@pytest.mark.parametrize("name", list(DATASETS))
def test_json_valid_against_official_schema(name, tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from validate_oscal import validate

    out = tmp_path / "p.json"
    write_oscal_json([Finding.from_dict(d) for d in DATASETS[name]], out)
    assert validate(JSON_SCHEMA, out) == []


@pytest.mark.skipif(not XSD.is_file(), reason="OSCAL XSD not downloaded")
@pytest.mark.parametrize("name", list(DATASETS))
def test_xml_valid_against_official_xsd(name, tmp_path):
    lxml = pytest.importorskip("lxml.etree")
    out = tmp_path / "p.xml"
    write_oscal_xml([Finding.from_dict(d) for d in DATASETS[name]], out)
    schema = lxml.XMLSchema(lxml.parse(str(XSD)))
    doc = lxml.parse(str(out))
    assert schema.validate(doc), [e.message for e in schema.error_log][:3]
