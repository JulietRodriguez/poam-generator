import pytest

from poam_generator.models import REQUIRED_FIELDS, Finding
from poam_generator.validate import validate_finding, validate_findings


def test_from_dict_and_csv_row(valid_dict):
    f = Finding.from_dict(valid_dict)
    row = f.to_csv_row()
    assert row["Weakness Name"] == "Test weakness"
    assert row["Milestones"] == "2026-02-01: Step one; Final verification"
    assert len(row) == len(REQUIRED_FIELDS)


def test_from_dict_splits_semicolon_milestones(valid_dict):
    valid_dict["milestones"] = "a; b ;; c"
    assert Finding.from_dict(valid_dict).milestones == ["a", "b", "c"]


def test_valid_finding_has_no_errors(valid_dict):
    assert validate_finding(valid_dict, 0) == []


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_each_required_field_is_enforced(valid_dict, field):
    valid_dict[field] = ""
    errors = validate_finding(valid_dict, 0)
    assert any(f"'{field}'" in e for e in errors)


@pytest.mark.parametrize(
    ("field", "value"),
    [("severity", "Extreme"), ("status", "Done"), ("source", "Rumor")],
)
def test_invalid_enumerations(valid_dict, field, value):
    valid_dict[field] = value
    errors = validate_finding(valid_dict, 0)
    assert len(errors) == 1 and f"Invalid {field}" in errors[0]


def test_aws_security_hub_is_a_valid_source(valid_dict):
    valid_dict["source"] = "AWS Security Hub"
    assert validate_finding(valid_dict, 0) == []


def test_milestones_type_checked(valid_dict):
    valid_dict["milestones"] = 42
    assert any("milestones" in e for e in validate_finding(valid_dict, 0))


def test_label_falls_back_to_index(valid_dict):
    valid_dict["weakness_name"] = ""
    assert validate_finding(valid_dict, 4)[0].startswith("[finding #5]")


def test_validate_findings(sample_raw):
    assert validate_findings(sample_raw) == []
    assert validate_findings([]) == ["No findings found in input file."]
