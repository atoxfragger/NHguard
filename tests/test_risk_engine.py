"""Tests unitaires pour risk_engine.compute_risk() — le moteur de score
central de tout le pipeline (voir behaviour_engine/temporal_correlator
qui réutilisent son THRESHOLDS/gate)."""

import risk_engine


def test_empty_signals_gives_baseline_confidence_and_zero_score():
    r = risk_engine.compute_risk({})
    assert r["score"] == 0
    assert r["severity"] == "low"
    assert r["threat_score"] == 0
    assert r["impact_score"] == 0
    assert r["confidence"] == risk_engine.BASELINE_CONFIDENCE_NO_SIGNAL


def test_compute_risk_accepts_none():
    # agent_alert() côté serveur ne passe jamais None, mais le module ne
    # doit pas dépendre de cette garantie de l'appelant (docstring : "s or {}").
    r = risk_engine.compute_risk(None)
    assert r["score"] == 0


def test_ioc_hash_match_alone_is_high_confidence_medium_severity():
    r = risk_engine.compute_risk({"ioc_hash_match": True})
    assert r["threat_score"] == risk_engine.THREAT_WEIGHTS["ioc_confirmed"]
    assert r["confidence"] == risk_engine.CONFIDENCE_WEIGHTS["ioc"]
    assert r["severity"] == "medium"
    assert r["score"] == 39


def test_known_bad_name_triggers_same_ioc_category_as_hash_match():
    # deux signaux DIFFERENTS alimentant la MEME catégorie "ioc" (voir
    # compute_risk : "s.get('ioc_hash_match') or s.get('known_bad_name')")
    # -- ne doivent jamais s'additionner, seulement se confirmer l'un l'autre.
    r_hash = risk_engine.compute_risk({"ioc_hash_match": True})
    r_name = risk_engine.compute_risk({"known_bad_name": True})
    r_both = risk_engine.compute_risk({"ioc_hash_match": True, "known_bad_name": True})
    assert r_hash["threat_score"] == r_name["threat_score"] == r_both["threat_score"]


def test_confidence_gate_caps_severity_when_confidence_low():
    """Un score élevé porté par une SEULE catégorie peu fiable (process,
    confiance 0.55) et un fichier de réputation "unknown" (pénalité
    ×0.85) tombe sous CONFIDENCE_GATE_THRESHOLD -- la sévérité affichée
    ne doit JAMAIS dépasser CONFIDENCE_GATE_MAX_SEVERITY dans ce cas,
    même si le score chiffré, lui, franchirait le seuil "high"."""
    signals = {"process_scoring": {
        "process": 80, "parent_child": 0, "file": 0,
        "reputation": "unknown", "details": [], "context": {},
    }}
    r = risk_engine.compute_risk(signals)
    assert r["confidence"] < risk_engine.CONFIDENCE_GATE_THRESHOLD
    assert risk_engine._severity_for_score(r["score"]) == "high"  # le score BRUT serait "high"...
    assert r["severity"] == risk_engine.CONFIDENCE_GATE_MAX_SEVERITY  # ...mais l'étiquette est plafonnée


def test_process_scoring_replaces_rather_than_adds_to_boolean_signals():
    """Documenté dans compute_risk() : quand process_scoring est fourni,
    il REMPLACE process/parent_child/file précisément -- ces 3 catégories
    ne doivent recevoir AUCUNE contribution des anciens booléens
    équivalents (process_suspect) s'ils sont présents en même temps. Les
    AUTRES catégories (ex: "reputation", dérivée de file_unknown) restent
    indépendantes et actives dans les deux cas -- ce ne sont PAS les
    mêmes catégories que celles remplacées par process_scoring, malgré
    l'observation sous-jacente parfois proche (voir le commentaire sur
    "reputation" dans risk_engine.py, qui documente ce chevauchement
    volontaire plutôt que de le cacher)."""
    only_scoring = risk_engine.compute_risk({
        "process_scoring": {"process": 50, "parent_child": 0, "file": 0,
                             "reputation": "known", "details": [], "context": {}},
    })
    scoring_plus_booleans = risk_engine.compute_risk({
        "process_scoring": {"process": 50, "parent_child": 0, "file": 0,
                             "reputation": "known", "details": [], "context": {}},
        "process_suspect": True,  # ne doit PAS s'ajouter à raw["process"]
    })
    assert only_scoring["threat_score"] == scoring_plus_booleans["threat_score"] == 50


def test_impact_alone_never_produces_a_score_without_threat():
    """Identité privilégiée / actif serveur sont des signaux d'IMPACT
    (gravité SI la menace est confirmée), jamais de menace en eux-mêmes —
    "le contexte renforce, il ne crée jamais la détection à lui seul"
    (voir le commentaire sur IMPACT_CONTRIBUTION dans risk_engine.py).
    Sans AUCUN signal threat, le score doit rester 0 même si les deux
    signaux impact sont actifs et que impact_score lui-même est élevé."""
    r = risk_engine.compute_risk({"admin_or_system_user": True, "server_asset": True})
    assert r["threat_score"] == 0
    assert r["impact_score"] > 0  # l'impact EST calculé...
    assert r["score"] == 0        # ...mais ne doit JAMAIS se traduire en score sans menace
    assert r["severity"] == "low"


def test_impact_still_reinforces_a_score_when_threat_is_present():
    """Le principe est "le contexte RENFORCE" -- pas "le contexte est
    ignoré" : avec un signal threat réel déjà présent, l'impact doit
    bien continuer à faire monter le score final."""
    without_impact = risk_engine.compute_risk({"ioc_hash_match": True})
    with_impact = risk_engine.compute_risk({
        "ioc_hash_match": True, "admin_or_system_user": True, "server_asset": True,
    })
    assert with_impact["threat_score"] == without_impact["threat_score"]
    assert with_impact["score"] > without_impact["score"]


def test_correlation_bonus_requires_at_least_three_active_threat_families():
    two_families = risk_engine.compute_risk({"ioc_hash_match": True, "persistence_path": True})
    three_families = risk_engine.compute_risk({
        "ioc_hash_match": True, "persistence_path": True, "ioc_ip_match": True,
    })
    assert "Corrélation" not in two_families["breakdown"]
    assert "Corrélation" in three_families["breakdown"]
    assert three_families["breakdown"]["Corrélation"] == risk_engine.THREAT_WEIGHTS["correlation_bonus"]


def test_score_and_threat_score_are_always_capped_0_to_100():
    # Empile un maximum de signaux threat simultanés -- le total brut
    # dépasserait 100 sans le plafond explicite dans compute_risk().
    signals = {
        "ioc_hash_match": True, "ioc_ip_match": True, "persistence_path": True,
        "ioc_cmdline_match": True, "process_suspect": True,
        "lolbin_parent_child": True, "file_unknown": True,
        "process_intelligence": {"is_new": True},
    }
    r = risk_engine.compute_risk(signals)
    assert 0 <= r["threat_score"] <= 100
    assert 0 <= r["score"] <= 100


def test_severity_thresholds_are_monotonic_boundaries():
    assert risk_engine._severity_for_score(0) == "low"
    assert risk_engine._severity_for_score(29) == "low"
    assert risk_engine._severity_for_score(30) == "medium"
    assert risk_engine._severity_for_score(59) == "medium"
    assert risk_engine._severity_for_score(60) == "high"
    assert risk_engine._severity_for_score(79) == "high"
    assert risk_engine._severity_for_score(80) == "critical"
    assert risk_engine._severity_for_score(100) == "critical"


# ── Réseau : IoC confirmé vs indice de port suspect ──────────

def test_suspicious_port_alone_is_a_weaker_signal_than_confirmed_ioc_ip():
    """Un port historiquement associé à un outil d'exploitation (voir
    SUSPICIOUS_PORTS dans edr_agent.py) est un INDICE, pas une preuve --
    doit rester nettement moins fort (score ET confiance) qu'une
    correspondance IoC IP confirmée, même si les deux alimentent la même
    famille "Réseau" au sens large."""
    port_only = risk_engine.compute_risk({"network_suspicious_port": True})
    ioc_only = risk_engine.compute_risk({"ioc_ip_match": True})
    assert port_only["threat_score"] < ioc_only["threat_score"]
    assert port_only["confidence"] < ioc_only["confidence"]


def test_suspicious_port_and_confirmed_ioc_add_up_as_distinct_observations():
    """Les deux catégories réseau (network / network_heuristic) sont
    SÉPARÉES précisément pour ne jamais faire porter la confiance d'un
    IoC confirmé à un simple indice de port -- mais rien n'empêche les
    deux de s'additionner quand ils se produisent réellement ensemble."""
    port = risk_engine.compute_risk({"network_suspicious_port": True})
    ioc = risk_engine.compute_risk({"ioc_ip_match": True})
    both = risk_engine.compute_risk({"ioc_ip_match": True, "network_suspicious_port": True})
    assert both["threat_score"] == port["threat_score"] + ioc["threat_score"]


# ── Contexte temporel (hors-horaires) ────────────────────────

def test_off_hours_alone_never_creates_a_score():
    """Même principe que les autres signaux IMPACT (voir
    test_impact_alone_never_produces_a_score_without_threat) : une
    exécution hors des heures ouvrées n'est un signal qu'en présence
    d'une menace déjà réelle, jamais à elle seule."""
    r = risk_engine.compute_risk({"off_hours": True})
    assert r["threat_score"] == 0
    assert r["score"] == 0


def test_off_hours_reinforces_an_existing_threat_score():
    with_context = risk_engine.compute_risk({"ioc_hash_match": True, "off_hours": True})
    without_context = risk_engine.compute_risk({"ioc_hash_match": True})
    assert with_context["threat_score"] == without_context["threat_score"]
    assert with_context["score"] > without_context["score"]
