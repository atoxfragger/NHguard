"""Tests unitaires pour process_scoring.score_ancestry()."""

import process_scoring


def test_empty_ancestry_returns_zeroed_unknown_result():
    r = process_scoring.score_ancestry([])
    assert r == {"process": 0, "parent_child": 0, "file": 0, "details": [],
                 "reputation": "unknown", "context": {}}


def test_lolbin_pattern_word_spawning_powershell_is_flagged():
    ancestry = [
        {"name": "explorer.exe", "path": r"C:\Windows\explorer.exe"},
        {"name": "winword.exe", "path": r"C:\Program Files\Office\winword.exe"},
        {"name": "powershell.exe", "path": r"C:\Windows\System32\powershell.exe"},
    ]
    r = process_scoring.score_ancestry(ancestry)
    assert r["parent_child"] >= process_scoring.PARENT_CHILD_RULES[("winword.exe", "powershell.exe")]
    assert any("winword.exe" in d["rule"] and "powershell.exe" in d["rule"] for d in r["details"])


def test_benign_ancestry_produces_no_parent_child_score():
    ancestry = [
        {"name": "explorer.exe", "path": r"C:\Windows\explorer.exe"},
        {"name": "chrome.exe", "path": r"C:\Program Files\Chrome\chrome.exe"},
    ]
    r = process_scoring.score_ancestry(ancestry)
    assert r["parent_child"] == 0


def test_confirmed_signature_overrides_unknown_reputation_for_uncatalogued_binary():
    """Un binaire non catalogué (absent de PROCESS_BASE_SCORES) mais dont
    la signature Authenticode a été confirmée (signed=True) doit être
    classé "signed", pas "unknown" -- signal de confiance indépendant du
    nom, voir le commentaire dans process_scoring.py."""
    ancestry_signed = [{"name": "un_binaire_inconnu.exe", "path": "C:\\x\\y.exe", "signed": True}]
    ancestry_unsigned = [{"name": "un_binaire_inconnu.exe", "path": "C:\\x\\y.exe", "signed": None}]
    assert process_scoring.score_ancestry(ancestry_signed)["reputation"] == "signed"
    assert process_scoring.score_ancestry(ancestry_unsigned)["reputation"] == "unknown"


def test_known_catalogued_name_is_reputation_known_even_with_zero_points():
    # explorer.exe est dans PROCESS_BASE_SCORES avec 0 point -- "connu et
    # sain" doit rester distinct de "jamais catalogué", même si le score
    # est identique (0 dans les deux cas) : la réputation alimente la
    # CONFIANCE du Risk Engine, pas le score lui-même.
    r = process_scoring.score_ancestry([{"name": "explorer.exe", "path": r"C:\Windows\explorer.exe"}])
    assert r["reputation"] == "known"
    assert r["process"] == 0
