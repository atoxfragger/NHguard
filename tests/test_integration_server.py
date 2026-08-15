"""Tests d'intégration bout-en-bout : vrai serveur Flask (test client) +
vraie base SQLite jetable (voir conftest.py:app_client), pas de mocks sur
la logique métier -- seul le SMTP réel est absent (voir _login_and_verify
qui lit le code 2FA directement dans PENDING_2FA plutôt que d'attendre un
email, aucun serveur SMTP n'étant configuré en test)."""

import db_data
import db_users
import edr_server


def _register(app_client, email="admin@test.local", password="Password1"):
    r = app_client.client.post("/api/register", json={
        "organization": "IntegrationOrg", "first_name": "A", "last_name": "B",
        "email": email, "password": password,
    })
    assert r.status_code == 201, r.get_json()
    return r.get_json()


def _login_and_get_session(app_client, email="admin@test.local", password="Password1"):
    r = app_client.client.post("/api/login", json={"username": email, "password": password})
    assert r.status_code == 200, r.get_json()
    temp_token = r.get_json()["temp_token"]
    code = edr_server.PENDING_2FA[temp_token]["code"]
    r2 = app_client.client.post("/api/verify-2fa", json={"temp_token": temp_token, "code": code})
    assert r2.status_code == 200, r2.get_json()
    return r2.get_json()["session_token"]


def _auth_headers(session_token):
    return {"Authorization": f"Bearer {session_token}"}


# ── Inscription / connexion ─────────────────────────────────

def test_register_then_login_then_authenticated_call(app_client):
    _register(app_client)
    session_token = _login_and_get_session(app_client)
    r = app_client.client.get("/api/stats", headers=_auth_headers(session_token))
    assert r.status_code == 200


def test_register_rejects_weak_password(app_client):
    r = app_client.client.post("/api/register", json={
        "organization": "X", "first_name": "A", "last_name": "B",
        "email": "x@test.local", "password": "short",
    })
    assert r.status_code == 400


def test_register_rejects_duplicate_email(app_client):
    _register(app_client, email="dupe@test.local")
    r = app_client.client.post("/api/register", json={
        "organization": "Autre", "first_name": "A", "last_name": "B",
        "email": "dupe@test.local", "password": "Password1",
    })
    assert r.status_code == 409


def test_wrong_2fa_code_is_rejected(app_client):
    _register(app_client)
    r = app_client.client.post("/api/login", json={"username": "admin@test.local", "password": "Password1"})
    temp_token = r.get_json()["temp_token"]
    r2 = app_client.client.post("/api/verify-2fa", json={"temp_token": temp_token, "code": "000000"})
    assert r2.status_code == 401


def test_unauthenticated_call_to_protected_route_is_rejected(app_client):
    r = app_client.client.get("/api/stats")
    assert r.status_code == 401


# ── Alertes / Risk Engine ───────────────────────────────────

def test_agent_alert_without_signals_uses_provided_severity(app_client):
    r = app_client.client.post("/api/agents/alert", json={
        "title": "Alerte simple", "severity": "high", "agent_id": "agent-1",
    }, headers=app_client.agent_headers)
    assert r.status_code == 201
    assert r.get_json()["severity"] == "high"
    assert r.get_json()["score"] is None  # pas de signaux -> pas de score du Risk Engine


def test_agent_alert_rejects_missing_required_fields(app_client):
    r = app_client.client.post("/api/agents/alert", json={"title": "incomplet"}, headers=app_client.agent_headers)
    assert r.status_code == 400


def test_agent_alert_rejects_invalid_severity(app_client):
    r = app_client.client.post("/api/agents/alert", json={
        "title": "x", "severity": "n_importe_quoi", "agent_id": "agent-1",
    }, headers=app_client.agent_headers)
    assert r.status_code == 400


def test_agent_alert_with_ioc_hash_signal_gets_scored_by_risk_engine(app_client):
    r = app_client.client.post("/api/agents/alert", json={
        "title": "Hash malveillant", "severity": "low", "agent_id": "agent-1",
        "signals": {"ioc_hash_match": True},
    }, headers=app_client.agent_headers)
    assert r.status_code == 201
    body = r.get_json()
    assert body["severity"] == "medium"  # voir test_risk_engine.py : ioc_hash_match seul -> medium
    assert body["score"] == 39


def test_wrong_agent_key_is_rejected(app_client):
    r = app_client.client.post("/api/agents/alert", json={
        "title": "x", "severity": "low", "agent_id": "agent-1",
    }, headers={"X-Agent-Key": "clé-invalide"})
    assert r.status_code == 401


# ── Policy Engine ────────────────────────────────────────────

def test_policy_engine_isolates_agent_on_matching_critical_alert(app_client):
    db_data.upsert_agent(app_client.org_id, "agent-1", "online", 5.0, 30.0, 40.0, "Windows 10", 50)
    r = app_client.client.post("/api/policies", json={
        "name": "auto-isolate", "action": "isolate", "min_severity": "high",
    }, headers=app_client.login_as_admin())
    assert r.status_code == 201

    r2 = app_client.client.post("/api/agents/alert", json={
        "title": "Détection critique", "severity": "high", "agent_id": "agent-1",
    }, headers=app_client.agent_headers)
    assert r2.status_code == 201

    pending = db_data.get_pending_commands(app_client.org_id, "agent-1")
    assert len(pending) == 1
    assert pending[0]["action"] == "isolate"


def test_no_policy_configured_means_no_automatic_action(app_client):
    db_data.upsert_agent(app_client.org_id, "agent-1", "online", 5.0, 30.0, 40.0, "Windows 10", 50)
    r = app_client.client.post("/api/agents/alert", json={
        "title": "Détection critique", "severity": "critical", "agent_id": "agent-1",
    }, headers=app_client.agent_headers)
    assert r.status_code == 201
    assert db_data.get_pending_commands(app_client.org_id, "agent-1") == []


# ── IoC ──────────────────────────────────────────────────────

def test_ioc_added_via_dashboard_is_visible_to_agents(app_client):
    r = app_client.client.post("/api/iocs", json={
        "type": "hash", "value": "deadbeef" * 8, "severity": "critical",
    }, headers=app_client.login_as_admin())
    assert r.status_code == 201

    r2 = app_client.client.get("/api/agents/iocs", headers=app_client.agent_headers)
    assert r2.status_code == 200
    values = [ioc["value"] for ioc in r2.get_json()]
    assert "deadbeef" * 8 in values


def test_ioc_rejects_unknown_type(app_client):
    r = app_client.client.post("/api/iocs", json={"type": "carrier_pigeon", "value": "x"},
                                headers=app_client.login_as_admin())
    assert r.status_code == 400


# ── Mise à jour de l'agent ──────────────────────────────────

def test_update_check_reports_no_update_when_nothing_published(app_client):
    r = app_client.client.get("/api/agents/update-check?version=1.0.0", headers=app_client.agent_headers)
    assert r.status_code == 200
    assert r.get_json()["update_available"] is False


def test_update_check_and_download_after_publish(app_client, tmp_path):
    import hashlib
    fake_exe = tmp_path / "fake.exe"
    fake_exe.write_bytes(b"CONTENU DE TEST")
    digest = hashlib.sha256(fake_exe.read_bytes()).hexdigest()

    import os
    os.makedirs(edr_server.UPDATES_DIR, exist_ok=True)
    dest = os.path.join(edr_server.UPDATES_DIR, "EDRAgent-9.9.9.exe")
    dest_bytes = fake_exe.read_bytes()
    with open(dest, "wb") as f:
        f.write(dest_bytes)
    db_data.set_latest_release("9.9.9", "EDRAgent-9.9.9.exe", digest)

    r = app_client.client.get("/api/agents/update-check?version=1.0.0", headers=app_client.agent_headers)
    assert r.get_json()["update_available"] is True
    assert r.get_json()["sha256"] == digest

    r2 = app_client.client.get("/api/agents/update-download", headers=app_client.agent_headers)
    assert r2.status_code == 200
    assert hashlib.sha256(r2.data).hexdigest() == digest

    try:
        os.remove(dest)
    except OSError:
        pass  # Windows peut garder le handle ouvert brièvement après send_from_directory
        # -- .pytest_modules/agent_updates est de toute façon jetable (gitignore), pas
        # la peine de faire échouer le test pour un fichier de test qui traîne.


# ── Commandes à distance ─────────────────────────────────────

def test_isolate_command_flows_from_dashboard_to_agent_and_back(app_client):
    db_data.upsert_agent(app_client.org_id, "agent-1", "online", 5.0, 30.0, 40.0, "Windows 10", 50)

    r = app_client.client.post("/api/agents/agent-1/isolate", headers=app_client.login_as_admin())
    assert r.status_code == 201
    command_id = r.get_json()["command_id"]

    r2 = app_client.client.get("/api/agents/commands?agent_id=agent-1", headers=app_client.agent_headers)
    commands = r2.get_json()
    assert len(commands) == 1 and commands[0]["action"] == "isolate"

    r3 = app_client.client.post(f"/api/agents/commands/{command_id}/result",
                                 json={"status": "done", "result": "isolé"},
                                 headers=app_client.agent_headers)
    assert r3.status_code == 200
    assert db_data.is_agent_isolated(app_client.org_id, "agent-1") is True


# ── Erreurs ──────────────────────────────────────────────────

def test_api_errors_are_always_json(app_client):
    r = app_client.client.get("/api/route/qui/nexiste/pas")
    assert r.status_code == 404
    assert r.content_type.startswith("application/json")
    assert "error" in r.get_json()
