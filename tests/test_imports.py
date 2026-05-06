"""Smoke tests: every public module must be importable on every supported platform.

These tests need no Windows hardware — they catch the class of bugs where a
module-level NameError or a missing re-export breaks ``import win32wifi``.
"""
import importlib
import unittest


class TestImports(unittest.TestCase):
    def test_import_package(self):
        importlib.import_module("win32wifi")

    def test_import_low_level_module(self):
        importlib.import_module("win32wifi.Win32NativeWifiApi")

    def test_import_high_level_module(self):
        importlib.import_module("win32wifi.Win32Wifi")

    def test_public_reexports_resolve(self):
        import win32wifi
        for name in (
            "getWirelessAvailableNetworkList",
            "getWirelessInterfaces",
            "getWirelessNetworkBssList",
            "getWirelessProfiles",
            "getWirelessProfileXML",
            "get_errno",
            "get_last_error",
        ):
            self.assertTrue(hasattr(win32wifi, name), f"win32wifi is missing {name!r}")

    def test_error_helpers_callable(self):
        from win32wifi import get_errno, get_last_error
        self.assertIsInstance(get_errno(), int)
        self.assertIsInstance(get_last_error(), int)


if __name__ == "__main__":
    unittest.main()
