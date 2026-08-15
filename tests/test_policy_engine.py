"""Tests unitaires pour policy_engine.evaluate_policies()."""

import policy_engine


POLICIES = [
    {"name": "auto-isolate critical", "enabled": True, "min_severity": "high",
     "min_confidence": 0.7, "category": None, "action": "isolate"},
    {"name": "notify anything medium+", "enabled": True, "min_severity": "medium",
     "min_confidence": None, "category": None, "action": "notify_only"},
    {"name": "only ransomware", "enabled": True, "min_severity": None,
     "min_confidence": None, "category": "ransomware", "action": "isolate"},
]


def test_critical_high_confidence_matches_isolate_and_notify():
    matched = policy_engine.evaluate_policies(
        POLICIES, {"severity": "critical", "confidence": 0.9, "category": "autre"}
    )
    assert {p["name"] for p in matched} == {"auto-isolate critical", "notify anything medium+"}


def test_high_severity_low_confidence_only_matches_notify():
    matched = policy_engine.evaluate_policies(
        POLICIES, {"severity": "high", "confidence": 0.3, "category": "autre"}
    )
    assert {p["name"] for p in matched} == {"notify anything medium+"}


def test_low_severity_matches_nothing():
    matched = policy_engine.evaluate_policies(
        POLICIES, {"severity": "low", "confidence": 0.99, "category": "autre"}
    )
    assert matched == []


def test_category_only_policy_ignores_severity_field():
    matched = policy_engine.evaluate_policies(
        POLICIES, {"severity": "low", "confidence": 0.1, "category": "ransomware"}
    )
    assert {p["name"] for p in matched} == {"only ransomware"}


def test_missing_confidence_never_silently_satisfies_a_min_confidence_policy():
    """Sécurité : si l'agent n'a pas fourni de confiance calculée (ex:
    ancien agent, alerte sans signaux détaillés), une politique qui EXIGE
    un min_confidence ne doit jamais matcher par défaut -- l'absence de
    donnée ne doit jamais se traduire en action automatique."""
    matched = policy_engine.evaluate_policies(
        POLICIES, {"severity": "critical", "confidence": None, "category": "autre"}
    )
    assert {p["name"] for p in matched} == {"notify anything medium+"}


def test_empty_policy_matches_everything():
    generic = [{"name": "catch-all", "enabled": True, "min_severity": None,
                "min_confidence": None, "category": None, "action": "notify_only"}]
    matched = policy_engine.evaluate_policies(generic, {"severity": "low", "confidence": 0.0, "category": None})
    assert len(matched) == 1


def test_severity_boundary_is_inclusive():
    policies = [{"name": "at least medium", "enabled": True, "min_severity": "medium",
                 "min_confidence": None, "category": None, "action": "notify_only"}]
    exactly_medium = policy_engine.evaluate_policies(policies, {"severity": "medium", "confidence": 1.0, "category": None})
    below = policy_engine.evaluate_policies(policies, {"severity": "low", "confidence": 1.0, "category": None})
    assert len(exactly_medium) == 1
    assert len(below) == 0
