"""Tests unitaires pour behaviour_engine.evaluate()."""

from datetime import datetime, timedelta

import behaviour_engine


def _alert(minutes_ago, now, category="malware", severity="high", alert_id="a1"):
    ts = (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")
    return {"id": alert_id, "timestamp": ts, "category": category, "severity": severity}


def test_no_alerts_no_chains_returns_none():
    assert behaviour_engine.evaluate([], agent_id="agent-1") is None


def test_single_alert_alone_never_proves_a_behaviour():
    now = datetime.utcnow()
    r = behaviour_engine.evaluate([_alert(1, now)], agent_id="agent-1", now=now)
    assert r is None


def test_two_alerts_within_window_can_produce_a_verdict():
    now = datetime.utcnow()
    alerts = [_alert(5, now, alert_id="a1"), _alert(3, now, alert_id="a2")]
    r = behaviour_engine.evaluate(alerts, agent_id="agent-1", now=now)
    # Deux alertes seules ne garantissent pas un verdict (dépend des
    # règles de tactiques/rafale) -- mais si un verdict EST produit,
    # l'agent_id fourni explicitement doit y apparaître, jamais déduit.
    if r is not None:
        assert "agent-1" in r["title"] or "agent-1" in r["description"]
        assert set(r["source_alert_ids"]) <= {"a1", "a2"}


def test_alerts_outside_correlation_window_are_excluded():
    now = datetime.utcnow()
    outside = behaviour_engine.CORRELATION_WINDOW_MINUTES + 10
    alerts = [_alert(outside, now, alert_id="old1"), _alert(outside + 2, now, alert_id="old2")]
    r = behaviour_engine.evaluate(alerts, agent_id="agent-1", now=now)
    assert r is None  # les deux alertes sont hors fenêtre -> aucune preuve utilisable


def test_temporal_chain_alone_can_trigger_without_any_alerts():
    """C'est exactement le scénario qui a motivé le paramètre agent_id
    explicite : temporal_chains peut produire un verdict avec `alerts`
    totalement vide -- il n'y aurait alors plus aucune alerte dont
    déduire la machine concernée, d'où l'obligation de le fournir."""
    now = datetime.utcnow()
    chain = {
        "confidence": 0.9, "pattern_name": "RTC-005", "scope_level": "process_tree",
        "source_alert_ids": [],
    }
    r = behaviour_engine.evaluate([], agent_id="agent-42", temporal_chains=[chain], now=now)
    assert r is not None
    assert "agent-42" in r["title"] or "agent-42" in r["description"]


def test_agent_id_defaults_to_placeholder_when_not_provided():
    now = datetime.utcnow()
    chain = {"confidence": 0.9, "pattern_name": "RTC-005", "scope_level": "process_tree", "source_alert_ids": []}
    r = behaviour_engine.evaluate([], temporal_chains=[chain], now=now)
    assert r is not None
    assert "?" in r["title"] or "?" in r["description"]
