"""
conftest.py — Rend les modules du dépôt importables par pytest.

Convention du dépôt : chaque fichier tracké est SANS extension et
utilise des espaces au lieu de underscores (ex: "data alerts" = le code
de db_data.py, "main serveur" = celui de edr_server.py) — un choix du
projet indépendant des tests, voir le README. `import db_data` ne
fonctionne donc pas tel quel : Python ne reconnaît pas "data alerts"
comme un module.

Plutôt que de maintenir des copies .py dupliquées à la main (source
d'oubli — une copie qui traîne, pas remise à jour après un changement
du fichier réel), ce conftest RECONSTRUIT ces copies à CHAQUE lancement
de la suite de tests, à partir du contenu actuel des fichiers trackés,
dans un dossier ignoré par git (voir .gitignore : .pytest_modules/).
Toujours à jour, jamais commité, jamais à maintenir manuellement.
"""

import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(REPO_ROOT, ".pytest_modules")

# module Python (nom d'import) -> fichier tracké (sans extension) source
MODULE_FILES = {
    "edr_agent": "agent",
    "antivirus_engine": "antivirus engine",
    "behaviour_engine": "behaviour engine",
    "db_data": "data alerts",
    "db_users": "data user",
    "event_queue": "event queue",
    "event_schema": "event schema",
    "edr_server": "main serveur",
    "policy_engine": "policy engine",
    "process_scoring": "process scoring",
    "process_tree": "process tree",
    "publish_update": "publish update",
    "risk_engine": "risk engine",
    "temporal_correlator": "temporal correlation",
    "edr_watchdog": "watchdog",
}


def _rebuild_module_copies():
    os.makedirs(BUILD_DIR, exist_ok=True)
    for module_name, tracked_name in MODULE_FILES.items():
        src = os.path.join(REPO_ROOT, tracked_name)
        dst = os.path.join(BUILD_DIR, f"{module_name}.py")
        shutil.copyfile(src, dst)


_rebuild_module_copies()
if BUILD_DIR not in sys.path:
    sys.path.insert(0, BUILD_DIR)


import pytest


@pytest.fixture(autouse=True)
def _no_real_smtp(monkeypatch):
    """Aucun test ne doit dépendre d'un serveur SMTP réel joignable — ni
    pour la vitesse (une vraie tentative de connexion/authentification
    peut prendre plusieurs secondes, y compris pour ÉCHOUER), ni pour la
    portabilité (un environnement de CI n'aura jamais les vraies
    identifiants Gmail configurés sur CETTE machine de développement).
    Le code 2FA lui-même est généré et stocké dans PENDING_2FA
    indépendamment de l'envoi -- voir _start_2fa dans main serveur --
    donc neutraliser l'envoi ne change rien à ce que les tests vérifient."""
    try:
        import edr_server
        monkeypatch.setattr(edr_server, "send_email", lambda *a, **k: None)
    except ImportError:
        pass  # tests purement unitaires qui n'importent jamais edr_server


class _AppClient:
    """Petit conteneur pour les tests d'intégration : un client Flask de
    test connecté à une base SQLite jetable et déjà initialisée, avec une
    organisation de test déjà créée — évite de répéter ce boilerplate
    dans chaque test."""

    def __init__(self, client, org, agent_key):
        self.client = client
        self.org = org
        self.org_id = org["id"]
        self.agent_key = agent_key
        self.agent_headers = {"X-Agent-Key": agent_key}

    def login_as_admin(self, email="admin@test.local", password="Password1"):
        """Crée un utilisateur admin DIRECTEMENT dans l'organisation déjà
        créée par cette fixture (self.org_id) et se connecte via le VRAI
        flux /api/login + /api/verify-2fa (le code 2FA est lu dans
        PENDING_2FA plutôt qu'attendu par email, aucun SMTP réel n'étant
        disponible en test).

        Piège à éviter : /api/register crée une NOUVELLE organisation à
        chaque appel — l'utiliser ici donnerait une session pour une
        organisation DIFFÉRENTE de self.org_id/self.agent_key, cassant
        silencieusement l'isolation multi-tenant plutôt que de la tester
        (constaté en écrivant les premiers tests d'intégration : des
        commandes/IoC créés via la session "disparaissaient" en lecture
        -- l'isolement fonctionnait EXACTEMENT comme prévu, c'était le
        test qui mélangeait deux organisations)."""
        import db_users
        from werkzeug.security import generate_password_hash

        db_users.create_user(
            org_id=self.org_id, email=email, first_name="Admin", last_name="Test",
            password_hash=generate_password_hash(password), role="admin",
        )
        r = self.client.post("/api/login", json={"username": email, "password": password})
        assert r.status_code == 200, r.get_json()
        temp_token = r.get_json()["temp_token"]

        import edr_server
        code = edr_server.PENDING_2FA[temp_token]["code"]
        r2 = self.client.post("/api/verify-2fa", json={"temp_token": temp_token, "code": code})
        assert r2.status_code == 200, r2.get_json()
        session_token = r2.get_json()["session_token"]
        return {"Authorization": f"Bearer {session_token}"}


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Base de données SQLite fraîche (dossier temporaire pytest, jamais
    la vraie edr_data.db/edr_users.db) + organisation de test déjà créée
    -- voir la discipline établie tout au long de ce projet : chaque test
    tourne contre une base réelle jetable, jamais mockée."""
    import db_data
    import db_users
    import edr_server

    monkeypatch.setattr(db_data, "DB_PATH", str(tmp_path / "test_data.db"))
    monkeypatch.setattr(db_users, "DB_PATH", str(tmp_path / "test_users.db"))
    db_data.init_db()
    db_users.init_db()

    org = db_users.create_organization("TestOrg")
    client = edr_server.app.test_client()
    return _AppClient(client, org, org["agent_api_key"])
