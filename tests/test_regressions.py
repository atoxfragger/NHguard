"""Tests de non-régression — chacun ancré sur un bug RÉEL trouvé et
corrigé au fil de ce projet (souvent via un test live ad hoc pendant la
session de développement elle-même). Le but de ce fichier n'est pas la
couverture générale (voir test_*.py pour les autres modules) mais de
verrouiller ces incidents précis pour qu'ils ne puissent jamais revenir
silencieusement lors d'un futur refactor."""

import os

import db_data
import db_users
import edr_server
import event_queue


# ── event_queue : connexion SQLite persistante ──────────────
#
# Bug original : next_seq()/enqueue() ouvraient chacun leur PROPRE
# connexion SQLite avec son propre commit synchrone -- mesuré en charge
# réelle à ~90ms/appel (~11 évènements/s). Fixé en passant à une
# connexion module-level persistante, réutilisée par tous les appels
# (voir _get_connection dans event_queue.py). Ce test ne mesure pas le
# temps (flaky) mais vérifie la PROPRIÉTÉ structurelle du fix : deux
# appels consécutifs doivent réutiliser le MÊME objet connexion, jamais
# en ouvrir une nouvelle à chaque fois.

def test_event_queue_reuses_a_single_persistent_connection(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setattr(event_queue, "_conn", None)
    event_queue.init_db()

    event_queue.next_seq()
    first_conn = event_queue._conn
    assert first_conn is not None

    event_queue.next_seq()
    event_queue.next_seq()
    assert event_queue._conn is first_conn  # jamais réouverte entre les appels


# ── antivirus_engine : la sévérité d'un blocage AV ne doit JAMAIS être
# recalculée par le Risk Engine ──
#
# Bug original : flush_av_block_queue() (edr_agent.py) envoyait l'alerte
# de blocage AV avec `signals={...}` -- dès que `signals` est fourni,
# agent_alert() (main serveur) ignore la `severity` fournie et la
# RECALCULE via risk_engine.compute_risk(), qui ne connaît rien du
# signal "antivirus_block" -> score ~0 -> une correspondance IoC
# critique confirmée s'affichait "low". Fixé en n'envoyant JAMAIS
# `signals` pour ce type d'alerte : un blocage AV est un verdict déjà
# définitif, pas un faisceau de signaux à faire re-scorer.

def test_antivirus_alert_severity_is_never_recomputed_by_risk_engine(app_client):
    r = app_client.client.post("/api/agents/alert", json={
        "title": "Fichier malveillant bloqué à l'écriture", "severity": "critical",
        "agent_id": "agent-1", "category": "antivirus",
        # PAS de "signals" ici -- c'est exactement ce que flush_av_block_queue()
        # doit faire (voir agent.py), et c'est ce que ce test verrouille.
    }, headers=app_client.agent_headers)
    assert r.status_code == 201
    body = r.get_json()
    assert body["severity"] == "critical"  # jamais recalculée à "low" par le Risk Engine


def test_regression_would_have_caught_severity_recompute_if_signals_were_sent(app_client):
    """Contre-test : prouve que le test ci-dessus détecterait vraiment
    le bug s'il revenait -- envoyer `signals` (même minimal, non reconnu
    du Risk Engine) sur la MÊME alerte fait bien tomber la sévérité,
    exactement comme dans l'incident original."""
    r = app_client.client.post("/api/agents/alert", json={
        "title": "x", "severity": "critical", "agent_id": "agent-1",
        "category": "antivirus", "signals": {"antivirus_block": True},
    }, headers=app_client.agent_headers)
    assert r.status_code == 201
    assert r.get_json()["severity"] != "critical"


# ── event_schema : tout event_type émis DOIT être enregistré ────
#
# Bug original : "dns_query" était émis par deux collecteurs
# (collect_network_events et collect_dns_events, voir agent.py) mais
# absent de EVENT_PRIORITY -- tombait silencieusement sur
# DEFAULT_PRIORITY (P2) au lieu de P1, sans qu'aucune erreur ne le
# signale. Trouvé lors de l'audit de stabilisation, pas en testant une
# fonctionnalité en particulier -- exactement le genre d'oubli qu'un
# test explicite doit verrouiller pour de bon.

import event_schema


def test_known_high_value_event_types_are_registered_with_expected_priority():
    expected = {
        "dns_query": "P1",
        "network_connect": "P1",
        "process_start": "P1",
        "malware_blocked": "P0",
        "agent_tampered": "P0",
    }
    for event_type, priority in expected.items():
        assert event_type in event_schema.EVENT_PRIORITY, (
            f"'{event_type}' est émis par l'agent mais absent de EVENT_PRIORITY "
            f"-- retombe silencieusement sur DEFAULT_PRIORITY"
        )
        assert event_schema.EVENT_PRIORITY[event_type] == priority


# ── Isolation multi-tenant : une session ne doit JAMAIS voir/agir sur
# les données d'une AUTRE organisation ──
#
# Pas un bug déjà rencontré dans ce produit précisément, mais un piège
# rencontré EN ÉCRIVANT les tests d'intégration eux-mêmes (deux
# organisations mélangées par erreur dans un premier jet de test,
# voir conftest.py:login_as_admin) -- assez proche d'un vrai risque de
# fuite entre clients pour mériter un verrou permanent explicite,
# plutôt que de rester une leçon apprise seulement en interne.

def test_session_from_one_org_cannot_see_another_orgs_agents(tmp_path, monkeypatch):
    monkeypatch.setattr(db_data, "DB_PATH", str(tmp_path / "data.db"))
    monkeypatch.setattr(db_users, "DB_PATH", str(tmp_path / "users.db"))
    db_data.init_db()
    db_users.init_db()

    org_a = db_users.create_organization("OrgA")
    org_b = db_users.create_organization("OrgB")
    db_data.upsert_agent(org_a["id"], "agent-a", "online", 1, 1, 1, "Windows", 10)
    db_data.upsert_agent(org_b["id"], "agent-b", "online", 1, 1, 1, "Windows", 10)

    from werkzeug.security import generate_password_hash
    db_users.create_user(org_id=org_a["id"], email="a@test.local", first_name="A", last_name="A",
                          password_hash=generate_password_hash("Password1"), role="admin")

    client = edr_server.app.test_client()
    r = client.post("/api/login", json={"username": "a@test.local", "password": "Password1"})
    temp_token = r.get_json()["temp_token"]
    code = edr_server.PENDING_2FA[temp_token]["code"]
    r2 = client.post("/api/verify-2fa", json={"temp_token": temp_token, "code": code})
    headers = {"Authorization": f"Bearer {r2.get_json()['session_token']}"}

    r3 = client.get("/api/agents", headers=headers)
    assert r3.status_code == 200
    seen_ids = {a["agent_id"] for a in r3.get_json()}
    assert seen_ids == {"agent-a"}
    assert "agent-b" not in seen_ids
