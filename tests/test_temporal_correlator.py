"""Tests unitaires pour temporal_correlator.correlate()/correlate_raw_events()."""

from datetime import datetime, timedelta

import temporal_correlator as tc


def _ts(now, offset_seconds):
    return (now + timedelta(seconds=offset_seconds)).isoformat(timespec="seconds")


def test_empty_events_returns_empty_list():
    assert tc.correlate([]) == []
    assert tc.correlate_raw_events([]) == []


def test_single_event_never_matches_a_multi_step_pattern():
    now = datetime.utcnow()
    events = [{"event_id": "e1", "pid": 100, "ppid": 50, "event_type": "process_start", "timestamp": _ts(now, 0)}]
    assert tc.correlate_raw_events(events) == []


def test_rtc005_full_chain_matches_at_process_tree_scope():
    """RTC-005 : process_start (parent) -> process_start (enfant) ->
    network_connect -> network_disconnect, tous rattachés au même arbre
    de processus (root_pid=100) -- le motif conçu dans ce module
    spécifiquement pour prouver une correspondance à l'échelle
    "process_tree" (voir sa docstring), pas seulement "host"."""
    now = datetime.utcnow()
    events = [
        {"event_id": "e1", "pid": 100, "ppid": 50, "event_type": "process_start", "timestamp": _ts(now, 0)},
        {"event_id": "e2", "pid": 200, "ppid": 100, "event_type": "process_start", "timestamp": _ts(now, 5)},
        {"event_id": "e3", "pid": 200, "ppid": 100, "event_type": "network_connect", "timestamp": _ts(now, 10)},
        {"event_id": "e4", "pid": 200, "ppid": 100, "event_type": "network_disconnect", "timestamp": _ts(now, 15)},
    ]
    chains = tc.correlate_raw_events(events)
    assert len(chains) == 1
    chain = chains[0]
    assert chain["pattern_id"] == "RTC-005"
    assert chain["scope_level"] == "process_tree"
    assert chain["completeness"] == 1.0
    assert chain["confidence"] == 1.0
    assert set(chain["source_event_ids"]) == {"e1", "e2", "e3", "e4"}


def test_events_outside_the_pattern_window_do_not_match():
    """Le motif RTC-005 a une fenêtre de 8 minutes -- des évènements
    autrement identiques mais étalés sur bien plus longtemps ne doivent
    PAS produire de correspondance."""
    now = datetime.utcnow()
    events = [
        {"event_id": "e1", "pid": 100, "ppid": 50, "event_type": "process_start", "timestamp": _ts(now, 0)},
        {"event_id": "e2", "pid": 200, "ppid": 100, "event_type": "process_start", "timestamp": _ts(now, 60 * 60)},
        {"event_id": "e3", "pid": 200, "ppid": 100, "event_type": "network_connect", "timestamp": _ts(now, 2 * 60 * 60)},
        {"event_id": "e4", "pid": 200, "ppid": 100, "event_type": "network_disconnect", "timestamp": _ts(now, 3 * 60 * 60)},
    ]
    chains = tc.correlate_raw_events(events)
    assert chains == []


def test_unrelated_process_tree_does_not_contaminate_a_process_tree_scoped_chain():
    """Un évènement d'un arbre de processus totalement séparé (racine
    différente) ne doit JAMAIS s'infiltrer dans une chaîne à l'échelle
    "process_tree" -- root_pid et la liste des évènements source de la
    chaîne RTC-005 (motif conçu pour matcher au niveau process_tree,
    voir sa docstring) doivent rester strictement ceux du bon arbre.
    Note : un AUTRE motif à l'échelle "host" (RTC-002, qui ne demande
    aucune continuité de pid par conception) peut légitimement matcher
    en plus sur ces mêmes évènements -- ce test ne porte que sur la
    chaîne process_tree elle-même, pas sur le nombre total de chaînes."""
    now = datetime.utcnow()
    events = [
        {"event_id": "e1", "pid": 100, "ppid": 50, "event_type": "process_start", "timestamp": _ts(now, 0)},
        {"event_id": "e2", "pid": 200, "ppid": 100, "event_type": "process_start", "timestamp": _ts(now, 5)},
        {"event_id": "e3", "pid": 200, "ppid": 100, "event_type": "network_connect", "timestamp": _ts(now, 10)},
        {"event_id": "e4", "pid": 200, "ppid": 100, "event_type": "network_disconnect", "timestamp": _ts(now, 15)},
        # Arbre totalement séparé, un seul évènement -- ne doit jamais
        # contaminer la chaîne process_tree ci-dessus.
        {"event_id": "e5", "pid": 999, "ppid": 1, "event_type": "process_start", "timestamp": _ts(now, 12)},
    ]
    chains = tc.correlate_raw_events(events)
    process_tree_chains = [c for c in chains if c["scope_level"] == "process_tree"]
    assert len(process_tree_chains) == 1
    assert process_tree_chains[0]["root_pid"] == 100
    assert "e5" not in process_tree_chains[0]["source_event_ids"]
