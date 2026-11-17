import json

import pytest
from click.testing import CliRunner

from poam_generator.cli import cli

from .conftest import SAMPLE


@pytest.fixture
def runner():
    return CliRunner()


def test_demo_writes_csv(runner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["demo"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "poam_output.csv").exists()


@pytest.mark.parametrize(("fmt", "suffix"), [("csv", "csv"), ("excel", "xlsx"), ("oscal", "json"), ("oscal-xml", "xml")])
def test_generate_each_format(runner, tmp_path, fmt, suffix):
    out = tmp_path / f"poam.{suffix}"
    result = runner.invoke(cli, ["generate", "-i", str(SAMPLE), "-o", str(out), "--format", fmt])
    assert result.exit_code == 0, result.output
    assert out.stat().st_size > 0


def test_generate_rejects_invalid_input(runner, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"weakness_name": "x"}]))
    result = runner.invoke(cli, ["generate", "-i", str(bad), "-o", str(tmp_path / "o.csv")])
    assert result.exit_code == 1
    assert "Missing required field" in result.output


def test_generate_rejects_malformed_json(runner, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    result = runner.invoke(cli, ["generate", "-i", str(bad), "-o", str(tmp_path / "o.csv")])
    assert result.exit_code == 1
    assert "Invalid JSON" in result.output


def test_validate_command(runner, tmp_path):
    assert runner.invoke(cli, ["validate", "-i", str(SAMPLE)]).exit_code == 0
    single = tmp_path / "one.json"
    single.write_text(json.dumps({"weakness_name": "x", "severity": "Extreme"}))
    result = runner.invoke(cli, ["validate", "-i", str(single)])
    assert result.exit_code == 1
    assert "Invalid severity" in result.output


def test_sync_mock_then_generate(runner, tmp_path):
    synced = tmp_path / "findings.json"
    result = runner.invoke(cli, ["sync", "--source", "aws-security-hub", "--mock", "-o", str(synced)])
    assert result.exit_code == 0, result.output
    # mock Security Hub findings must pass the same validation as everything else
    gen = runner.invoke(cli, ["generate", "-i", str(synced), "-o", str(tmp_path / "p.json"), "--format", "oscal"])
    assert gen.exit_code == 0, gen.output


def test_track_and_status(runner, tmp_path):
    db = tmp_path / "t.db"
    first = runner.invoke(cli, ["track", "-i", str(SAMPLE), "--db", str(db)])
    assert first.exit_code == 0, first.output
    assert "New finding" in first.output
    again = runner.invoke(cli, ["track", "-i", str(SAMPLE), "--db", str(db)])
    assert "No changes since last run" in again.output
    status = runner.invoke(cli, ["status", "--db", str(db)])
    assert status.exit_code == 0, status.output


def test_status_without_db(runner, tmp_path):
    result = runner.invoke(cli, ["status", "--db", str(tmp_path / "missing.db")])
    assert result.exit_code == 1
