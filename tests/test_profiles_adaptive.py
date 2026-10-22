"""Perfiles automáticos adaptados al sistema y modo sudo."""

import copy
import os
import types
import unittest
from pathlib import Path
from unittest import mock

from vela import cli, profiles

from .helpers import ENV


class AdaptiveProfilesTests(unittest.TestCase):
    def test_defaults_are_added_to_cfg(self):
        env = copy.deepcopy(ENV)
        cfg = {"profiles": {"default": {"description": "x"}}}
        added = profiles.merge_adaptive(cfg, env)
        self.assertIn("diario", cfg["profiles"])
        self.assertIn("privado", cfg["profiles"])
        self.assertIn("anonimo", cfg["profiles"])
        self.assertIn("alto_riesgo", cfg["profiles"])
        self.assertIn("laboratorio", cfg["profiles"])
        self.assertEqual(set(added), {"diario", "privado", "anonimo", "alto_riesgo", "laboratorio"})

    def test_system_without_tor_or_proxies_gets_fewer_profiles(self):
        env = copy.deepcopy(ENV)
        env["tor"] = {"installed": False, "running": False, "control": [], "socks": [], "browser": [], "torrc": {},
                      "transports": []}
        env["proxy"] = {"local": [], "ssh_tunnels": [], "proxychains": None, "env": {}, "desktop": None}
        cfg = {"profiles": {"default": {}}}
        profiles.merge_adaptive(cfg, env)
        self.assertEqual(set(cfg["profiles"]), {"default", "diario", "privado"})

    def test_untouched_auto_profile_adapts_when_system_changes(self):
        env = copy.deepcopy(ENV)
        env["interfaces"] = [i for i in env["interfaces"] if i["kind"] == "ethernet"]
        env["vpn"] = {"providers": {}, "networkmanager": [], "wireguard": {"configs": [], "readable": True},
                      "openvpn_configs": []}
        env["killswitch"] = {"clients": [], "declared_by": []}
        cfg = {"profiles": {"default": {}}}
        profiles.merge_adaptive(cfg, env)
        self.assertFalse(cfg["profiles"]["diario"]["require_vpn"])

        env2 = copy.deepcopy(ENV)   # ahora hay wg0 y VPN en NetworkManager
        profiles.merge_adaptive(cfg, env2)
        self.assertTrue(cfg["profiles"]["diario"]["require_vpn"])

    def test_user_edit_wins(self):
        env = copy.deepcopy(ENV)
        cfg = {"profiles": {"default": {}}}
        profiles.merge_adaptive(cfg, env)
        cfg["profiles"]["diario"]["retention_days"] = 3
        profiles.merge_adaptive(cfg, env)
        self.assertEqual(cfg["profiles"]["diario"]["retention_days"], 3)

    def test_auto_marker_not_written_to_toml(self):
        env = copy.deepcopy(ENV)
        cfg = {"profiles": {"default": {}}}
        profiles.merge_adaptive(cfg, env)
        text = profiles.to_toml(cfg["profiles"], {"default"})
        self.assertNotIn("_auto", text)
        self.assertNotIn("_auto_sig", text)


class SudoTests(unittest.TestCase):
    def test_drop_is_noop_without_root(self):
        # En los tests no somos root: la función no debe reejecutar ni lanzar nada.
        cli._drop_sudo_privileges(["status"])

    def test_install_script_accepts_sudo(self):
        self.assertIn("VELA_INSTALL_AS_USER", Path("install.sh").read_text(encoding="utf-8"))

    def test_sudo_reexecs_as_invoking_user(self):
        pw = types.SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir="/tmp/alice")
        with mock.patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=False), \
                mock.patch.object(os, "geteuid", return_value=0), \
                mock.patch("pwd.getpwnam", return_value=pw), \
                mock.patch.object(os, "setgid"), mock.patch.object(os, "setgroups"), \
                mock.patch.object(os, "getgrouplist", return_value=[1000]), \
                mock.patch.object(os, "setuid"), mock.patch.object(os, "execvpe") as ex:
            cli._drop_sudo_privileges(["status"])
        self.assertEqual(ex.call_args.args[1][-3:], ["-m", "vela", "status"])
        self.assertEqual(ex.call_args.args[2]["HOME"], "/tmp/alice")


if __name__ == "__main__":
    unittest.main()
