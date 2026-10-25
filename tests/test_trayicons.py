"""Iconos de la bandeja: emblema de VELA con insignia de estado, solo emblema o símbolos del sistema."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import config, trayicons

try:
    import cairo  # noqa: F401
    HAS_CAIRO = True
except ImportError:
    HAS_CAIRO = False


def pixel(path: Path, x: int, y: int):
    import cairo
    s = cairo.ImageSurface.create_from_png(str(path))
    data, stride = s.get_data(), s.get_stride()
    b, g, r, a = data[y * stride + 4 * x: y * stride + 4 * x + 4]
    return r, g, b, a


@unittest.skipUnless(HAS_CAIRO, "pycairo no disponible")
class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_every_state_and_style(self):
        for style in ("vela", "vela_plain"):
            for st in trayicons.STATES:
                p = trayicons.render(st, style, 64, self.tmp)
                self.assertTrue(p.exists())
                self.assertEqual(p.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(len(list(self.tmp.glob("*.png"))), 8)

    def test_badge_color_matches_state(self):
        r = 64 * 0.22
        cx = cy = int(64 - r - 1)
        for st, col in trayicons.BADGE.items():
            p = trayicons.render(st, "vela", 64, self.tmp)
            got = pixel(p, cx, cy - int(r * 0.78))        # dentro de la insignia, por encima del glifo
            want = tuple(int(col[i:i + 2], 16) for i in (1, 3, 5))
            self.assertTrue(all(abs(a - b) <= 6 for a, b in zip(got[:3], want)), (st, got, want))

    def test_plain_has_no_badge_and_off_is_dimmed(self):
        on = trayicons.render("ok", "vela_plain", 64, self.tmp)
        off = trayicons.render("off", "vela_plain", 64, self.tmp)
        self.assertNotEqual(on.read_bytes(), off.read_bytes())
        self.assertEqual(trayicons.render("ok", "vela_plain", 64, self.tmp).read_bytes(),
                         trayicons.render("alert", "vela_plain", 64, self.tmp).read_bytes())

    def test_cached_file_is_reused(self):
        p = trayicons.render("warn", "vela", 64, self.tmp)
        mtime = p.stat().st_mtime_ns
        self.assertEqual(trayicons.render("warn", "vela", 64, self.tmp), p)
        self.assertEqual(p.stat().st_mtime_ns, mtime)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            trayicons.render("nope", "vela", 64, self.tmp)
        with self.assertRaises(ValueError):
            trayicons.render("ok", "status", 64, self.tmp)


class StyleTests(unittest.TestCase):
    def test_status_style_uses_system_symbols(self):
        self.assertEqual(trayicons.icon_for("ok", "status"), "security-high-symbolic")
        self.assertEqual(trayicons.icon_for("off", "status"), "network-offline-symbolic")

    @unittest.skipUnless(HAS_CAIRO, "pycairo no disponible")
    def test_vela_style_returns_png_path(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        with mock.patch.object(trayicons, "icon_dir", lambda: tmp):
            path = trayicons.icon_for("alert", "vela")
            self.assertTrue(path.startswith(str(tmp)) and path.endswith(".png"))
            self.assertTrue(trayicons.icon_for("alert", "desconocido").endswith(".png"))   # estilo raro → predeterminado

    def test_preference_is_read_and_validated(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        f = tmp / "app-settings.toml"
        with mock.patch.dict(os.environ, {"VELA_SETTINGS": str(f)}):
            self.assertEqual(trayicons.current_style(), "vela")                # predeterminado
            config.set_ui_pref("tray_icon", "status")
            self.assertEqual(trayicons.current_style(), "status")
            with self.assertRaises(ValueError):
                config.set_ui_pref("tray_icon", "otro")
            f.write_text('[ui]\ntray_icon = "otro"\n')
            self.assertEqual(trayicons.current_style(), "vela")                # valor corrupto → predeterminado


if __name__ == "__main__":
    unittest.main()
