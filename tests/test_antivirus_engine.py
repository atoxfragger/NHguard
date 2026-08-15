"""Tests unitaires pour antivirus_engine.scan_file_for_threats() et ses
helpers. La chaîne EICAR réelle n'est PAS écrite sur disque dans ces
tests : ce fichier peut tourner sur une machine avec un antivirus tiers
actif (voir CI), qui interceptrait/quarantinerait le fichier de test
avant même qu'on puisse le relire (constaté en développement sur une
machine avec Windows Defender actif) -- non pas un bug de ce module.
La détection EICAR elle-même est vérifiée via une lecture simulée
(monkeypatch), qui exerce exactement le même chemin de code."""

import hashlib
import io
import os

import antivirus_engine as av


def test_eicar_pattern_is_the_canonical_68_byte_string():
    # Empreinte SHA-256 publiquement documentée du fichier de test EICAR
    # standard -- confirme que la chaîne intégrée est bien la référence
    # officielle, pas une approximation.
    digest = hashlib.sha256(av.EICAR_TEST_STRING.encode("ascii")).hexdigest()
    assert len(av.EICAR_TEST_STRING) == 68
    assert digest == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_eicar_detection_via_content_pattern(monkeypatch):
    eicar_bytes = av.EICAR_TEST_STRING.encode("ascii")
    monkeypatch.setattr(os.path, "getsize", lambda path: len(eicar_bytes))
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.BytesIO(eicar_bytes))

    verdict = av.scan_file_for_threats("/chemin/simule/eicar.com", {}, av.default_content_patterns())
    assert verdict is not None
    assert verdict["kind"] == "content_pattern"
    assert verdict["ioc"]["value"] == "EICAR"


def test_clean_file_produces_no_verdict(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("Ceci est un document parfaitement normal.")
    verdict = av.scan_file_for_threats(str(f), {}, av.default_content_patterns())
    assert verdict is None


def test_hash_match_against_known_ioc(tmp_path):
    f = tmp_path / "payload.exe"
    f.write_bytes(b"CONTENU DE TEST MARQUE MALVEILLANT")
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    known_hashes = {digest: {"description": "IoC de test", "severity": "critical"}}

    verdict = av.scan_file_for_threats(str(f), known_hashes, [])
    assert verdict is not None
    assert verdict["kind"] == "hash"
    assert verdict["hash"] == digest


def test_unrelated_hash_does_not_match(tmp_path):
    f = tmp_path / "payload.exe"
    f.write_bytes(b"CONTENU INOFFENSIF")
    known_hashes = {"0" * 64: {"description": "hash sans rapport"}}
    verdict = av.scan_file_for_threats(str(f), known_hashes, [])
    assert verdict is None


def test_oversized_file_is_skipped_without_error(tmp_path):
    f = tmp_path / "enorme.bin"
    with open(f, "wb") as fh:
        fh.seek(av.MAX_SCAN_SIZE_BYTES + 1)
        fh.write(b"\0")
    verdict = av.scan_file_for_threats(str(f), {"deadbeef": {}}, av.default_content_patterns())
    assert verdict is None


def test_missing_file_returns_none_not_an_exception(tmp_path):
    missing = tmp_path / "nexiste_pas.exe"
    assert av.scan_file_for_threats(str(missing), {}, []) is None


def test_custom_content_pattern_from_org_configured_ioc(tmp_path):
    patterns = av.load_content_patterns([
        {"type": "content_pattern", "value": "RANSOM_MARKER_XYZ",
         "severity": "critical", "description": "IoC organisation"},
    ])
    # Le motif intégré EICAR doit toujours être présent EN PLUS du motif personnalisé.
    assert len(patterns) == 2

    f = tmp_path / "note.txt"
    f.write_text("bonjour RANSOM_MARKER_XYZ au milieu du texte")
    verdict = av.scan_file_for_threats(str(f), {}, patterns)
    assert verdict is not None
    assert verdict["ioc"]["description"] == "IoC organisation"


def test_load_content_patterns_ignores_other_ioc_types():
    patterns = av.load_content_patterns([
        {"type": "hash", "value": "deadbeef"},
        {"type": "ip", "value": "1.2.3.4"},
    ])
    assert len(patterns) == 1  # seulement le motif EICAR intégré
