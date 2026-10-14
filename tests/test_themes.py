"""Motor de temas: tokens completos, contraste WCAG verificado, semántica estable y preferencias."""

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import config, themes

HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


class TokenTests(unittest.TestCase):
    def test_five_themes_light_and_dark(self):
        self.assertEqual(themes.ids(), ["signature", "obsidian", "glacier", "sentinel", "contrast"])
        self.assertEqual(themes.DEFAULT_THEME, "signature")
        for tid in themes.ids():
            th = themes.get(tid)
            self.assertTrue(th["name"].startswith("VELA "))
            self.assertTrue(th["description"])
            for mode in ("light", "dark"):
                missing = [t for t in themes.TOKENS if t not in th[mode]]
                self.assertEqual(missing, [], f"{tid}/{mode}")
                bad = {k: v for k, v in th[mode].items() if not HEX.match(v)}
                self.assertEqual(bad, {}, f"{tid}/{mode}")

    def test_light_and_dark_really_differ(self):
        for tid in themes.ids():
            light, dark = themes.tokens(tid, False), themes.tokens(tid, True)
            self.assertGreater(themes.luminance(light["bg"]), themes.luminance(dark["bg"]))
            self.assertGreater(themes.luminance(dark["ink"]), themes.luminance(light["ink"]))

    def test_unknown_theme_falls_back_to_signature(self):
        self.assertEqual(themes.get("nope")["name"], "VELA Signature")
        self.assertEqual(themes.get(None)["name"], "VELA Signature")


class ContrastTests(unittest.TestCase):
    def test_wcag_math(self):
        self.assertAlmostEqual(themes.contrast("#000000", "#FFFFFF"), 21.0, places=2)
        self.assertAlmostEqual(themes.contrast("#777777", "#777777"), 1.0, places=6)
        self.assertAlmostEqual(themes.contrast("#767676", "#FFFFFF"), 4.54, places=2)

    def test_every_theme_and_mode_meets_its_minimums(self):
        for tid in themes.ids():
            for dark in (False, True):
                checks = themes.contrast_checks(tid, dark)
                self.assertGreater(len(checks), 70)
                fails = [(d, round(got, 2), need) for d, _fg, _bg, need, got in checks if got < need]
                self.assertEqual(fails, [], f"{tid} {'dark' if dark else 'light'}")

    def test_high_contrast_text_reaches_aaa(self):
        for dark in (False, True):
            t = themes.tokens("contrast", dark)
            for bg in themes.TEXT_BGS:
                self.assertGreaterEqual(themes.contrast(t["ink"], t[bg]), 7.0)
                self.assertGreaterEqual(themes.contrast(t["ink2"], t[bg]), 7.0)

    def test_connection_types_are_distinguishable(self):
        for tid in themes.ids():
            for dark in (False, True):
                self.assertEqual(themes.distinct_checks(tid, dark), [], f"{tid} {dark}")


class SemanticTests(unittest.TestCase):
    """Los colores de estado no cambian de significado entre temas ni se confunden con la marca."""

    def test_meanings_are_shared(self):
        for tid in themes.ids():
            for dark in (False, True):
                t = themes.tokens(tid, dark)
                self.assertEqual(t["net_leak"], t["danger"], tid)          # fuga = peligro
                self.assertEqual(t["net_direct"], t["serious"], tid)       # directa = naranja (grave)
                self.assertEqual(t["net_protected"], t["success"], tid)    # protegida = éxito

    def test_states_hue_families(self):
        """Tor violeta, directa naranja, fuga roja, protegida verde: comprobado por el tono (OKLab)."""
        import math

        def hue(c):
            _l, a, b = themes.oklab(c)
            return math.degrees(math.atan2(b, a)) % 360
        for tid in themes.ids():
            for dark in (False, True):
                t = themes.tokens(tid, dark)
                self.assertTrue(110 <= hue(t["net_protected"]) <= 165, (tid, dark, hue(t["net_protected"])))
                self.assertTrue(35 <= hue(t["net_direct"]) <= 75, (tid, dark, hue(t["net_direct"])))
                self.assertTrue(hue(t["net_leak"]) <= 35 or hue(t["net_leak"]) >= 340, (tid, dark, hue(t["net_leak"])))
                self.assertTrue(290 <= hue(t["net_tor"]) <= 345, (tid, dark, hue(t["net_tor"])))

    def test_brand_accent_is_not_a_state(self):
        for tid in themes.ids():
            for dark in (False, True):
                t = themes.tokens(tid, dark)
                for state in ("net_protected", "success", "danger", "warning"):
                    self.assertGreaterEqual(themes.delta_e(t["accent_text"], t[state]), 15, (tid, dark, state))


class PrefsTests(unittest.TestCase):
    def test_clean_prefs(self):
        self.assertEqual(themes.clean_prefs(None), themes.PREF_DEFAULTS)
        p = themes.clean_prefs({"theme": "GLACIER", "appearance": "light", "density": "compact", "motion": "x"})
        self.assertEqual(p, {"theme": "glacier", "appearance": "light", "density": "compact", "motion": "system"})

    def test_resolve_dark(self):
        self.assertTrue(themes.resolve_dark("dark", False))
        self.assertFalse(themes.resolve_dark("light", True))
        self.assertTrue(themes.resolve_dark("system", True))
        self.assertFalse(themes.resolve_dark("system", False))

    def test_load_prefs_reads_settings_file_and_env(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "app-settings.toml"
            f.write_text('[ui]\ntheme = "sentinel"\nappearance = "dark"\ndensity = "compact"\n')
            env = {k: v for k, v in os.environ.items() if k not in ("VELA_THEME", "VELA_APPEARANCE")}
            env["VELA_SETTINGS"] = str(f)
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(themes.load_prefs(), {"theme": "sentinel", "appearance": "dark",
                                                       "density": "compact", "motion": "system"})
                os.environ["VELA_THEME"] = "obsidian"
                self.assertEqual(themes.load_prefs()["theme"], "obsidian")
            f.write_text("esto no es toml [[[")
            with mock.patch.dict(os.environ, {"VELA_SETTINGS": str(f)}):
                self.assertEqual(themes.load_prefs()["theme"], "signature")

    def test_settings_keys_registered(self):
        for key in ("ui.theme", "ui.appearance", "ui.density", "ui.motion"):
            self.assertIn(key, config.SETTINGS_KEYS)
        self.assertEqual(config.DEFAULTS["ui"]["theme"], "signature")
        self.assertEqual(config.DEFAULTS["ui"]["appearance"], "system")


class OutputTests(unittest.TestCase):
    def test_web_css_has_both_modes(self):
        css = themes.web_css("glacier")
        self.assertIn(':root[data-theme="light"]', css)
        self.assertIn(':root, :root[data-theme="dark"]', css)
        for var in themes.WEB_VARS:
            self.assertEqual(css.count(f"{var}:"), 2, var)

    def test_gtk_css_parses_without_errors(self):
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
            from gi.repository import Gtk
            from vela.native import theme as native_theme
        except (ImportError, ValueError):
            self.skipTest("GTK 4 / libadwaita no disponible")
        for tid in themes.ids():
            for dark in (False, True):
                for density in themes.DENSITIES:
                    for css_vars in (True, False):
                        errors = []
                        prov = Gtk.CssProvider()
                        prov.connect("parsing-error", lambda _p, _s, err: errors.append(err.message))
                        prov.load_from_string(native_theme.build_css(themes.tokens(tid, dark), density, css_vars))
                        self.assertEqual(errors, [], (tid, dark, density, css_vars))

    def test_gtk_css_uses_tokens_not_fixed_colors(self):
        try:
            from vela.native import theme as native_theme
        except (ImportError, ValueError):
            self.skipTest("GTK 4 / libadwaita no disponible")
        t = themes.tokens("obsidian", False)
        css = native_theme.build_css(t, "comfortable", True)
        literals = set(re.findall(r"#[0-9a-fA-F]{6}\b", css))
        allowed = {v.lower() for v in t.values()} | {"#000000"}
        self.assertEqual({c for c in literals if c.lower() not in allowed and
                          c.lower() != themes.mix(t["destructive"], "#000000", 0.12).lower()}, set())


if __name__ == "__main__":
    unittest.main()
