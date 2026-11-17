import sys
import types

import pytest

from poam_generator import aws_sync
from poam_generator.validate import validate_findings


@pytest.mark.parametrize(
    ("label", "expected"),
    [("CRITICAL", "Critical"), ("high", "High"), ("MEDIUM", "Medium"), ("LOW", "Low"), ("INFORMATIONAL", "Medium")],
)
def test_map_severity(label, expected):
    assert aws_sync._map_severity(label) == expected


@pytest.mark.parametrize(
    ("record", "workflow", "expected"),
    [("ARCHIVED", "NEW", "Closed"), ("ACTIVE", "RESOLVED", "Closed"), ("ACTIVE", "NOTIFIED", "In Progress"), ("ACTIVE", "NEW", "Open")],
)
def test_map_status(record, workflow, expected):
    assert aws_sync._map_status(record, workflow) == expected


def test_fmt_date():
    assert aws_sync._fmt_date("2026-05-01T12:30:00.000Z") == "2026-05-01"
    assert len(aws_sync._fmt_date("garbage")) == 10  # falls back to today


def test_mock_findings_pass_validation():
    assert validate_findings(aws_sync.MOCK_FINDINGS) == []


class _FakePaginator:
    def __init__(self, pages):
        self.pages = pages
        self.kwargs = None

    def paginate(self, **kwargs):
        self.kwargs = kwargs
        return self.pages


def test_fetch_security_hub_findings_maps_fields(monkeypatch):
    raw = {
        "Title": "S3 general purpose buckets should block public read access",
        "Description": "desc",
        "AwsAccountId": "111122223333",
        "Resources": [{"Id": "arn:aws:s3:::bucket"}],
        "Compliance": {"SecurityControlId": "S3.2"},
        "Severity": {"Label": "CRITICAL"},
        "ProductName": "Security Hub",
        "FirstObservedAt": "2026-05-01T00:00:00Z",
        "Remediation": {"Recommendation": {"Text": "Block public access."}},
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "Id": "finding-1",
    }
    paginator = _FakePaginator([{"Findings": [raw, {"Title": "No compliance block"}]}])
    client = types.SimpleNamespace(get_paginator=lambda name: paginator)
    calls = {}

    def fake_client(service, region_name):
        calls["service"], calls["region"] = service, region_name
        return client

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=fake_client))
    out = aws_sync.fetch_security_hub_findings("us-gov-west-1")

    assert calls == {"service": "securityhub", "region": "us-gov-west-1"}
    assert paginator.kwargs["Filters"]["RecordState"][0]["Value"] == "ACTIVE"
    first, second = out
    assert first["security_control"] == "S3.2"
    assert first["severity"] == "Critical"
    assert first["source"] == "AWS Security Hub"
    assert first["office_org"] == "111122223333 / arn:aws:s3:::bucket"
    assert first["detection_date"] == "2026-05-01"
    assert first["comments"] == "Finding ID: finding-1; Product: Security Hub"
    assert second["security_control"] == "UNKNOWN"
    assert second["office_org"].endswith("Unknown resource")


def test_fetch_without_boto3_raises(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(RuntimeError, match="boto3 is required"):
        aws_sync.fetch_security_hub_findings("us-east-1")
