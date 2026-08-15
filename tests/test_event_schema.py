"""Tests unitaires pour event_schema.py — make_event()/validate_event()."""

import event_schema


def test_make_event_has_all_required_top_level_fields():
    ev = event_schema.make_event("process_start", "agent-1", 42, data={"pid": 123}, os_name="Windows")
    for field in event_schema.REQUIRED_TOP_LEVEL:
        assert field in ev
    assert ev["schema_version"] == event_schema.SCHEMA_VERSION
    assert ev["event"]["type"] == "process_start"
    assert ev["host"]["id"] == "agent-1"
    assert ev["host"]["os"] == "windows"  # toujours en minuscules


def test_make_event_uses_registered_priority():
    ev = event_schema.make_event("agent_tampered", "agent-1", 1)
    assert ev["event"]["priority"] == "P0"


def test_make_event_falls_back_to_default_priority_for_unregistered_type():
    ev = event_schema.make_event("un_type_totalement_inconnu", "agent-1", 1)
    assert ev["event"]["priority"] == event_schema.DEFAULT_PRIORITY


def test_every_registered_priority_is_a_valid_level():
    for event_type, priority in event_schema.EVENT_PRIORITY.items():
        assert priority in ("P0", "P1", "P2", "P3"), f"{event_type} a une priorité invalide : {priority}"


def test_validate_event_accepts_a_freshly_made_event():
    ev = event_schema.make_event("network_connect", "agent-1", 1, data={"dst": "1.2.3.4"})
    ok, reason = event_schema.validate_event(ev)
    assert ok is True
    assert reason is None


def test_validate_event_rejects_non_dict():
    ok, reason = event_schema.validate_event("ceci n'est pas un dict")
    assert ok is False
    assert reason


def test_validate_event_rejects_missing_required_field():
    ev = event_schema.make_event("process_start", "agent-1", 1)
    del ev["seq"]
    ok, reason = event_schema.validate_event(ev)
    assert ok is False
    assert "seq" in reason


def test_validate_event_rejects_wrong_schema_version():
    ev = event_schema.make_event("process_start", "agent-1", 1)
    ev["schema_version"] = 999
    ok, reason = event_schema.validate_event(ev)
    assert ok is False


def test_validate_event_rejects_missing_event_type():
    ev = event_schema.make_event("process_start", "agent-1", 1)
    ev["event"]["type"] = ""
    ok, reason = event_schema.validate_event(ev)
    assert ok is False


def test_validate_event_rejects_missing_host_id():
    ev = event_schema.make_event("process_start", "", 1)
    ok, reason = event_schema.validate_event(ev)
    assert ok is False


def test_validate_event_rejects_non_dict_data():
    ev = event_schema.make_event("process_start", "agent-1", 1)
    ev["data"] = "pas un objet"
    ok, reason = event_schema.validate_event(ev)
    assert ok is False
