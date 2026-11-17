import json
from pathlib import Path

import pytest

from poam_generator.models import Finding

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample_findings.json"


@pytest.fixture
def sample_raw() -> list[dict]:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


@pytest.fixture
def sample_findings(sample_raw) -> list[Finding]:
    return [Finding.from_dict(d) for d in sample_raw]


@pytest.fixture
def valid_dict() -> dict:
    return {
        "weakness_name": "Test weakness",
        "weakness_description": "Description.",
        "security_control": "AC-2",
        "severity": "High",
        "source": "Audit",
        "detection_date": "2026-01-01",
        "scheduled_completion": "2026-03-01",
        "office_org": "IT",
        "point_of_contact": "ISSO",
        "resources_required": "8 hrs",
        "remediation_plan": "Fix it.",
        "milestones": ["2026-02-01: Step one", "Final verification"],
        "status": "Open",
        "comments": "None.",
    }
