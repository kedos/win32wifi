# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - 2024 Shaked Gitelman
#
# Forked from: PyWiWi - <https://github.com/6e726d/PyWiWi>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Andres Blanco     (6e726d)    <6e726d@gmail.com>
# Author: Shaked Gitelman   (almondg)   <shaked.dev@gmail.com>
#

"""Integration tests against a real ``wlanapi.dll`` on Windows.

Skipped by default. Run with ``pytest -m hardware`` on a Windows host that
has at least one wireless adapter present.
"""
import threading
import unittest
from ctypes import addressof

import pytest

from win32wifi.Win32NativeWifiApi import (
    ERROR_SUCCESS,
    Win32WifiError,
    WlanCloseHandle,
    WlanEnumInterfaces,
    WlanFreeMemory,
    WlanGetNetworkBssList,
    WlanOpenHandle,
    WlanRegisterNotification,
    WlanScan,
)


@pytest.mark.hardware
class TestWin32NativeWifiApi(unittest.TestCase):

    def setUp(self):
        # CI runners (and headless VMs in general) often have no wireless
        # adapter and the WLAN AutoConfig service stopped, so WlanOpenHandle
        # raises with ERROR_SERVICE_NOT_ACTIVE (1062). On non-Windows hosts
        # ``wlanapi.dll`` is missing and ``_check_wlanapi`` raises
        # RuntimeError. Either way: skip rather than fail — these tests
        # cannot meaningfully run without a real wifi stack.
        try:
            handle = WlanOpenHandle()
        except (Win32WifiError, RuntimeError) as exc:
            self.skipTest(f"No usable WLAN stack on this host: {exc}")
        WlanCloseHandle(handle)

    def test_wlan_open_close_handle_success(self):
        handle = WlanOpenHandle()
        result = WlanCloseHandle(handle)
        self.assertEqual(result, ERROR_SUCCESS)

    def test_wlan_enum_interfaces_success(self):
        handle = WlanOpenHandle()
        try:
            wlan_ifaces = WlanEnumInterfaces(handle)
            try:
                data_type = wlan_ifaces.contents.InterfaceInfo._type_
                num = wlan_ifaces.contents.NumberOfItems
                ifaces_pointer = addressof(wlan_ifaces.contents.InterfaceInfo)
                wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
                self.assertGreaterEqual(len(wlan_iface_info_list), 0, "Expected at least 0 interfaces.")
            finally:
                WlanFreeMemory(wlan_ifaces)
        finally:
            WlanCloseHandle(handle)

    def test_wlan_scan_success(self):
        handle = WlanOpenHandle()
        try:
            wlan_ifaces = WlanEnumInterfaces(handle)
            try:
                data_type = wlan_ifaces.contents.InterfaceInfo._type_
                num = wlan_ifaces.contents.NumberOfItems
                if num > 0:
                    ifaces_pointer = addressof(wlan_ifaces.contents.InterfaceInfo)
                    wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)

                    ssid = "test"
                    for wlan_iface_info in wlan_iface_info_list:
                        WlanScan(handle, wlan_iface_info.InterfaceGuid, ssid)
            finally:
                WlanFreeMemory(wlan_ifaces)
        finally:
            WlanCloseHandle(handle)

    def test_wlan_get_network_bss_list_success(self):
        handle = WlanOpenHandle()
        try:
            wlan_ifaces = WlanEnumInterfaces(handle)
            try:
                data_type = wlan_ifaces.contents.InterfaceInfo._type_
                num = wlan_ifaces.contents.NumberOfItems
                if num > 0:
                    ifaces_pointer = addressof(wlan_ifaces.contents.InterfaceInfo)
                    wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
                    for wlan_iface_info in wlan_iface_info_list:
                        iface_guid = wlan_iface_info.InterfaceGuid
                        bss_list = WlanGetNetworkBssList(handle, iface_guid)
                        try:
                            self.assertGreaterEqual(bss_list.contents.NumberOfItems, 0)
                        finally:
                            WlanFreeMemory(bss_list)
            finally:
                WlanFreeMemory(wlan_ifaces)
        finally:
            WlanCloseHandle(handle)

    def test_wlan_register_notification(self):
        handle = WlanOpenHandle()
        try:
            ev = threading.Event()

            def callback(wnd, p):
                ev.set()

            # Just register and unregister to see if it doesn't crash.
            # ``_cb`` keeps the C callback wrapper alive for the duration of
            # the wait — the binding is intentional even though we never read it.
            _cb = WlanRegisterNotification(handle, callback)
            ev.wait(1) # We don't necessarily expect a notification immediately
        finally:
            WlanCloseHandle(handle)

if __name__ == "__main__":
    unittest.main()
