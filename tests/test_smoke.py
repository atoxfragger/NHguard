"""Vérifie que tous les modules du dépôt s'importent correctement — le
premier filet de sécurité : si un seul module a une erreur de syntaxe ou
un import cassé, TOUTE la suite de tests échouerait à la collection sans
que la cause soit évidente. Ce test isole ce cas précis."""

import conftest


def test_all_tracked_modules_import_cleanly():
    import importlib
    for module_name in conftest.MODULE_FILES:
        importlib.import_module(module_name)
