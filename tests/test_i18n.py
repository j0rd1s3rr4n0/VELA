"""Traducciones: catálogos completos, variables intactas, detección del idioma y respaldo seguro."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import i18n


class CatalogTests(unittest.TestCase):
    def test_every_language_complete_and_placeholders_match(self):
        rep = i18n.check(verbose=False)
        for lang, r in rep.items():
            self.assertEqual(r["missing"], [], f"{lang}: faltan traducciones")
            self.assertEqual(r["bad_placeholders"], [], f"{lang}: variables distintas")

    def test_technical_strings_are_not_translatable(self):
        keys = i18n.extract()
        for k in keys:
            self.assertNotRegex(k, r"\bORDER BY\b|\bAND \w+=\?|meta skuid|AUTHENTICATE|charset=|M-SEARCH",
                                "texto técnico marcado como traducible")
        self.assertNotIn("gitguard: allow", keys)


class RuntimeTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language(None)

    def test_translate_and_format(self):
        i18n.set_language("en")
        self.assertEqual(i18n._("Túnel caído") if "Túnel caído" in i18n.catalog("en") else "x", "x")
        self.assertEqual(i18n._("Ajustes"), "Settings")
        self.assertEqual(i18n._("Perfil activo: {name}", name="diario"), "Active profile: diario")
        i18n.set_language("de")
        self.assertEqual(i18n._("Ajustes"), "Einstellungen")
        i18n.set_language("es")
        self.assertEqual(i18n._("Perfil activo: {name}", name="x"), "Perfil activo: x")

    def test_unknown_text_and_broken_translation_fall_back(self):
        i18n.set_language("fr")
        self.assertEqual(i18n._("texto que no existe en ningún catálogo"), "texto que no existe en ningún catálogo")
        with mock.patch.dict(i18n._catalogs, {"fr": {"Hola {name}": "Salut {nom}"}}):
            self.assertEqual(i18n._("Hola {name}", name="Ana"), "Hola Ana")   # nunca rompe

    def test_detection_order(self):
        with tempfile.TemporaryDirectory() as d:
            s = Path(d) / "app-settings.toml"
            env = {"VELA_SETTINGS": str(s), "LANG": "pt_BR.UTF-8", "LANGUAGE": "", "LC_ALL": "", "LC_MESSAGES": ""}
            with mock.patch.dict(os.environ, env):
                os.environ.pop("VELA_LANG", None)
                self.assertEqual(i18n.detect(), "pt")                       # del sistema
                s.write_text('[ui]\nlanguage = "ca"\n')
                self.assertEqual(i18n.detect(), "ca")                       # el ajuste manda
                os.environ["VELA_LANG"] = "de"
                self.assertEqual(i18n.detect(), "de")                       # la variable manda sobre todo
                os.environ["VELA_LANG"] = ""
                s.write_text('[ui]\nlanguage = "auto"\n')
                os.environ["LANG"] = "ja_JP.UTF-8"
                self.assertEqual(i18n.detect(), "en")                       # idioma sin traducción: inglés

    def test_cli_lang_option(self):
        out = subprocess.run([sys.executable, "-m", "vela", "--lang", "fr", "--help"], capture_output=True, text=True,
                             env={**os.environ, "VELA_NO_MIGRATE": "1"}, timeout=60).stdout
        self.assertIn("langue de l'interface", out)


if __name__ == "__main__":
    unittest.main()
