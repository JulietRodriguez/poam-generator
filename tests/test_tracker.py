from datetime import date, timedelta

import pytest

from poam_generator import tracker


def _item(item_id, status="Open", due=None, name="Weakness"):
    return {
        "item_id": item_id,
        "weakness_name": name,
        "security_control": "AC-2",
        "severity": "High",
        "status": status,
        "detection_date": "2026-01-01",
        "scheduled_completion": due or "2026-12-31",
        "office_org": "IT",
        "point_of_contact": "ISSO",
    }


@pytest.fixture
def db(tmp_path):
    return tmp_path / "tracker.db"


def test_first_save_reports_new_findings(db):
    changes = tracker.save_findings([_item("V-001"), _item("V-002")], db_path=db)
    assert [c["type"] for c in changes] == ["new", "new"]
    assert len(tracker.get_all_findings(db_path=db)) == 2


def test_resave_without_changes_reports_nothing(db):
    tracker.save_findings([_item("V-001")], db_path=db)
    assert tracker.save_findings([_item("V-001")], db_path=db) == []


def test_status_change_is_recorded_in_history(db):
    tracker.save_findings([_item("V-001", "Open")], db_path=db)
    changes = tracker.save_findings([_item("V-001", "In Progress")], db_path=db)
    assert changes == [{"item_id": "V-001", "type": "status_change", "old": "Open", "new": "In Progress"}]
    history = tracker.get_status_history("V-001", db_path=db)
    assert history[0]["old_status"] == "Open"
    assert history[0]["new_status"] == "In Progress"
    assert history[0]["notes"] == "Auto-detected on sync"


def test_update_status(db):
    tracker.save_findings([_item("V-001")], db_path=db)
    assert tracker.update_status("V-001", "Closed", notes="Verified by rescan", db_path=db)
    assert tracker.update_status("V-001", "Closed", db_path=db)  # no-op, still found
    assert not tracker.update_status("V-999", "Closed", db_path=db)
    history = tracker.get_status_history("V-001", db_path=db)
    assert len(history) == 1 and history[0]["notes"] == "Verified by rescan"
    assert tracker.get_status_history("V-999", db_path=db) == []


def test_overdue_and_due_this_week(db):
    today = date.today()
    items = [
        _item("V-001", due=(today - timedelta(days=5)).isoformat()),
        _item("V-002", due=(today + timedelta(days=3)).isoformat()),
        _item("V-003", due=(today + timedelta(days=30)).isoformat()),
        _item("V-004", status="Closed", due=(today - timedelta(days=5)).isoformat()),
        _item("V-005", status="Risk Accepted", due=(today + timedelta(days=1)).isoformat()),
    ]
    tracker.save_findings(items, db_path=db)
    assert [f["item_id"] for f in tracker.get_overdue_findings(db_path=db)] == ["V-001"]
    assert [f["item_id"] for f in tracker.get_due_this_week(db_path=db)] == ["V-002"]


def test_days_remaining():
    assert tracker.days_remaining((date.today() + timedelta(days=10)).isoformat()) == 10
    assert tracker.days_remaining((date.today() - timedelta(days=2)).isoformat()) == -2
    assert tracker.days_remaining("not-a-date") == 0
