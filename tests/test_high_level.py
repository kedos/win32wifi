"""High-level ``Win32Wifi`` tests.

These tests mock the *Python-level* ``Win32NativeWifiApi.Wlan*`` wrappers
rather than the underlying DLL, so we can hand back fully-formed ctypes
structures and assert that the high-level wrappers unwrap them correctly.
"""
import ctypes
import logging
import threading
import warnings
from ctypes import c_bool, c_long, c_ulong
from unittest.mock import patch

import pytest

from win32wifi import Win32Wifi
from win32wifi.Win32NativeWifiApi import (
    HANDLE,
    WLAN_AVAILABLE_NETWORK_LIST,
    WLAN_BSS_LIST,
    WLAN_INTERFACE_INFO_LIST,
    WLAN_PROFILE_INFO_LIST,
    WLAN_RADIO_STATE,
    Win32WifiError,
)


def _make_handle():
    """Return a non-zero ``HANDLE`` so wrappers don't treat it as null."""
    return HANDLE(12345)


def _patch_handle_lifecycle():
    """Patch the low-level handle open/close/free so tests don't need the DLL."""
    return (
        patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()),
        patch.object(Win32Wifi, "WlanCloseHandle", return_value=0),
        patch.object(Win32Wifi, "WlanFreeMemory", return_value=None),
    )


# ---------------------------------------------------------------------------
# Interface enumeration
# ---------------------------------------------------------------------------

def test_get_wireless_interfaces_unwraps_list():
    iface_list = WLAN_INTERFACE_INFO_LIST()
    iface_list.NumberOfItems = 1
    iface_list.Index = 0
    iface_list.InterfaceInfo[0].strInterfaceDescription = "Mock Adapter"
    iface_list.InterfaceInfo[0].isState = 1  # connected

    open_p, close_p, free_p = _patch_handle_lifecycle()
    with open_p, close_p, free_p, \
         patch.object(Win32Wifi, "WlanEnumInterfaces",
                      return_value=ctypes.pointer(iface_list)):
        ifaces = Win32Wifi.getWirelessInterfaces()

    assert len(ifaces) == 1
    assert ifaces[0].description == "Mock Adapter"
    assert ifaces[0].state_string == "wlan_interface_state_connected"


def test_get_wireless_interfaces_empty_list_returns_empty():
    iface_list = WLAN_INTERFACE_INFO_LIST()
    iface_list.NumberOfItems = 0

    open_p, close_p, free_p = _patch_handle_lifecycle()
    with open_p, close_p, free_p, \
         patch.object(Win32Wifi, "WlanEnumInterfaces",
                      return_value=ctypes.pointer(iface_list)):
        assert Win32Wifi.getWirelessInterfaces() == []


# ---------------------------------------------------------------------------
# Available networks / BSS list
# ---------------------------------------------------------------------------

def _fake_iface():
    iface_list = WLAN_INTERFACE_INFO_LIST()
    iface_list.NumberOfItems = 1
    iface_list.InterfaceInfo[0].strInterfaceDescription = "Mock"
    iface_list.InterfaceInfo[0].isState = 4  # disconnected
    return Win32Wifi.WirelessInterface(iface_list.InterfaceInfo[0])


def test_get_available_networks_unwraps_signal_quality_and_ssid():
    net_list = WLAN_AVAILABLE_NETWORK_LIST()
    net_list.NumberOfItems = 1
    net = net_list.Network[0]
    ssid_bytes = b"MyHomeNet"
    net.dot11Ssid.SSIDLength = len(ssid_bytes)
    net.dot11Ssid.SSID = ssid_bytes + b"\x00" * (32 - len(ssid_bytes))
    net.dot11BssType = 1  # infrastructure
    net.NumberOfBssids = 1
    net.NetworkConnectable = 1
    net.NumberOfPhyTypes = 1
    net.wlanSignalQuality = 73
    net.SecurityEnabled = 1
    net.dot11DefaultAuthAlgorithm = 7  # RSNA_PSK
    net.dot11DefaultCipherAlgorithm = 0x04  # CCMP

    open_p, close_p, free_p = _patch_handle_lifecycle()
    with open_p, close_p, free_p, \
         patch.object(Win32Wifi, "WlanGetAvailableNetworkList",
                      return_value=ctypes.pointer(net_list)):
        networks = Win32Wifi.getWirelessAvailableNetworkList(_fake_iface())

    assert len(networks) == 1
    assert networks[0].ssid == b"MyHomeNet"
    assert networks[0].signal_quality == 73
    assert networks[0].security_enabled is True
    assert networks[0].auth == "DOT11_AUTH_ALGO_RSNA_PSK"
    assert networks[0].cipher == "DOT11_CIPHER_ALGO_CCMP"


def test_get_bss_list_decodes_bssid_and_ssid():
    bss_list = WLAN_BSS_LIST()
    bss_list.NumberOfItems = 1
    bss_list.dwTotalSize = ctypes.sizeof(WLAN_BSS_LIST)
    entry = bss_list.wlanBssEntries[0]
    ssid_bytes = b"BSS-Net"
    entry.dot11Ssid.SSIDLength = len(ssid_bytes)
    entry.dot11Ssid.SSID = ssid_bytes + b"\x00" * (32 - len(ssid_bytes))
    entry.dot11Bssid = (ctypes.c_ubyte * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
    entry.dot11BssType = 1
    entry.dot11BssPhyType = 7  # HT
    entry.LinkQuality = 99
    entry.Rssi = -42
    entry.IeOffset = 0
    entry.IeSize = 0  # no information elements

    open_p, close_p, free_p = _patch_handle_lifecycle()
    with open_p, close_p, free_p, \
         patch.object(Win32Wifi, "WlanGetNetworkBssList",
                      return_value=ctypes.pointer(bss_list)):
        bsses = Win32Wifi.getWirelessNetworkBssList(_fake_iface())

    assert len(bsses) == 1
    assert bsses[0].bssid == "AA:BB:CC:DD:EE:FF"
    assert bsses[0].ssid == b"BSS-Net"
    assert bsses[0].rssi == -42
    assert bsses[0].phy_type == "dot11_phy_type_ht"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

def test_get_wireless_profiles_parses_xml_ssid():
    profile_list = WLAN_PROFILE_INFO_LIST()
    profile_list.NumberOfItems = 1
    profile_list.ProfileInfo[0].ProfileName = "MyProfile"
    profile_list.ProfileInfo[0].Flags = 0

    sample_xml = (
        '<?xml version="1.0"?>'
        '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
        '<name>MyProfile</name>'
        '<SSIDConfig><SSID><name>MySSID</name></SSID></SSIDConfig>'
        '</WLANProfile>'
    )
    xml_buffer = ctypes.create_unicode_buffer(sample_xml)

    open_p, close_p, free_p = _patch_handle_lifecycle()
    with open_p, close_p, free_p, \
         patch.object(Win32Wifi, "WlanGetProfileList",
                      return_value=ctypes.pointer(profile_list)), \
         patch.object(Win32Wifi, "WlanGetProfile",
                      return_value=ctypes.cast(xml_buffer, ctypes.c_wchar_p)):
        profiles = Win32Wifi.getWirelessProfiles(_fake_iface())

    assert len(profiles) == 1
    assert profiles[0].name == "MyProfile"
    assert profiles[0].ssid == "MySSID"


def test_wireless_profile_handles_malformed_xml():
    """Bad XML must not raise — the wrapper falls back to ssid=None."""
    profile_info = WLAN_PROFILE_INFO_LIST().ProfileInfo[0]
    profile_info.ProfileName = "Broken"
    profile_info.Flags = 0
    p = Win32Wifi.WirelessProfile(profile_info, "<not-actually-xml")
    assert p.name == "Broken"
    assert p.ssid is None


# ---------------------------------------------------------------------------
# connect() — parameter packing
# ---------------------------------------------------------------------------

def test_connect_packs_profile_and_ssid_into_connection_params():
    """``connect()`` must build a properly populated WLAN_CONNECTION_PARAMETERS."""
    iface = _fake_iface()
    params = {
        "connectionMode": "wlan_connection_mode_profile",
        "profile": "MyProfile",
        "ssid": "MySSID",
        "bssType": "dot11_BSS_type_infrastructure",
        "flags": 0,
    }

    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanConnect", return_value=0) as m_connect:
        Win32Wifi.connect(iface, params)

    assert m_connect.called, "WlanConnect was never invoked"
    # Args: (handle, guid, WLAN_CONNECTION_PARAMETERS)
    _handle, _guid, packed = m_connect.call_args[0]
    assert packed.strProfile == "MyProfile"
    ssid = packed.pDot11_ssid.contents.SSID[: packed.pDot11_ssid.contents.SSIDLength]
    assert bytes(ssid) == b"MySSID"


def test_connect_rejects_missing_profile_for_profile_mode():
    iface = _fake_iface()
    params = {
        "connectionMode": "wlan_connection_mode_profile",
        "profile": None,
        "ssid": "MySSID",
        "bssType": "dot11_BSS_type_infrastructure",
        "flags": 0,
    }
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0):
        with pytest.raises(Win32WifiError):
            Win32Wifi.connect(iface, params)


# ---------------------------------------------------------------------------
# Disconnect / delete profile
# ---------------------------------------------------------------------------

def test_disconnect_calls_wlan_disconnect_with_iface_guid():
    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanDisconnect", return_value=0) as m_disc:
        Win32Wifi.disconnect(iface)
    assert m_disc.called
    assert m_disc.call_args[0][1] is iface.guid


def test_delete_profile_returns_native_result_code():
    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanDeleteProfile", return_value=0) as m_del:
        result = Win32Wifi.deleteProfile(iface, "ProfileToZap")
    assert result == 0
    assert m_del.call_args[0][2] == "ProfileToZap"


# ---------------------------------------------------------------------------
# queryInterface — single-value return + opcode decoding
# ---------------------------------------------------------------------------

def _patch_query_interface(return_value):
    """Helper: patch WlanQueryInterface to return ``ctypes.pointer(return_value)``."""
    return patch.object(
        Win32Wifi, "WlanQueryInterface",
        return_value=ctypes.pointer(return_value),
    )


def test_query_interface_returns_decoded_value_not_tuple():
    """``queryInterface`` must NOT return the legacy ``(None, value)`` tuple."""
    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanFreeMemory", return_value=None), \
         _patch_query_interface(c_long(-57)):
        out = Win32Wifi.queryInterface(iface, "rssi")
    assert out == -57


def test_query_interface_rssi_returns_signed_int():
    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanFreeMemory", return_value=None), \
         _patch_query_interface(c_long(-72)):
        out = Win32Wifi.queryInterface(iface, "rssi")
    assert isinstance(out, int)
    assert out == -72


def test_query_interface_channel_number_returns_unsigned_int():
    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanFreeMemory", return_value=None), \
         _patch_query_interface(c_ulong(149)):
        out = Win32Wifi.queryInterface(iface, "channel_number")
    assert out == 149


def test_query_interface_autoconf_enabled_coerces_to_bool():
    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanFreeMemory", return_value=None), \
         _patch_query_interface(c_bool(True)):
        out = Win32Wifi.queryInterface(iface, "autoconf_enabled")
    assert out is True
    assert isinstance(out, bool)


def test_query_interface_radio_state_decodes_phy_list():
    radio = WLAN_RADIO_STATE()
    radio.dwNumberOfPhys = 2
    radio.PhyRadioState[0].dwPhyIndex = 0
    radio.PhyRadioState[0].dot11SoftwareRadioState = 1  # on
    radio.PhyRadioState[0].dot11HardwareRadioState = 1
    radio.PhyRadioState[1].dwPhyIndex = 1
    radio.PhyRadioState[1].dot11SoftwareRadioState = 2  # off
    radio.PhyRadioState[1].dot11HardwareRadioState = 1

    iface = _fake_iface()
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, "WlanFreeMemory", return_value=None), \
         _patch_query_interface(radio):
        out = Win32Wifi.queryInterface(iface, "radio_state")

    assert isinstance(out, list)
    assert len(out) == 2
    assert out[0]["dot11SoftwareRadioState"] == "dot11_radio_state_on"
    assert out[1]["dot11SoftwareRadioState"] == "dot11_radio_state_off"
    assert out[1]["dwPhyIndex"] == 1


def test_query_interface_unknown_opcode_raises_value_error():
    iface = _fake_iface()
    with pytest.raises(ValueError, match="Unknown opcode item"):
        Win32Wifi.queryInterface(iface, "this_does_not_exist")


# ---------------------------------------------------------------------------
# setPsdIeDataList — placeholder must fail loudly
# ---------------------------------------------------------------------------

def test_set_psd_ie_data_list_raises_not_implemented():
    with pytest.raises(NotImplementedError, match="setPsdIeDataList"):
        Win32Wifi.setPsdIeDataList("AB", [b"\x01\x02"])


# ---------------------------------------------------------------------------
# Hosted Network helpers — must emit DeprecationWarning
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("func_name,call_args", [
    ("hostedNetworkForceStart", ()),
    ("hostedNetworkForceStop", ()),
    ("hostedNetworkInitSettings", ()),
    ("hostedNetworkRefreshSecuritySettings", ()),
    ("hostedNetworkStartUsing", ()),
    ("hostedNetworkStopUsing", ()),
])
def test_hosted_network_helpers_emit_deprecation_warning(func_name, call_args):
    target = getattr(Win32Wifi, func_name)
    wlan_func_name = "Wlan" + func_name[0].upper() + func_name[1:]
    with patch.object(Win32Wifi, "WlanOpenHandle", return_value=_make_handle()), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0), \
         patch.object(Win32Wifi, wlan_func_name, return_value=0):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            target(*call_args)
    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecations, f"{func_name} should emit DeprecationWarning"
    assert "Hosted Network" in str(deprecations[0].message)


# ---------------------------------------------------------------------------
# Notification cleanup — thread safety + proper deregister
# ---------------------------------------------------------------------------

def test_unregister_notification_calls_register_with_null_callback():
    """Per Microsoft docs, deregistering means calling WlanRegisterNotification
    again with a NULL callback. Closing the handle alone leaks the OS-side
    registration."""
    fake_handle = _make_handle()
    callback_sentinel = object()
    notification = Win32Wifi.NotificationObject(fake_handle, callback_sentinel)

    with Win32Wifi._notif_lock:
        Win32Wifi._notif_handles.append(fake_handle)
        Win32Wifi._notif_callbacks.append(callback_sentinel)

    with patch.object(Win32Wifi, "WlanRegisterNotification", return_value=None) as m_reg, \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0) as m_close:
        Win32Wifi.unregisterNotification(notification)

    # First positional arg = handle, second = callback (must be None to deregister)
    assert m_reg.called
    assert m_reg.call_args[0][0] is fake_handle
    assert m_reg.call_args[0][1] is None
    assert m_close.called
    # Bookkeeping must be empty afterwards.
    assert fake_handle not in Win32Wifi._notif_handles
    assert callback_sentinel not in Win32Wifi._notif_callbacks


def test_unregister_notification_is_idempotent():
    """Calling unregister twice on the same object must be a no-op the second time."""
    fake_handle = _make_handle()
    callback_sentinel = object()
    notification = Win32Wifi.NotificationObject(fake_handle, callback_sentinel)
    # NOT registered — _notif_handles is empty.
    with patch.object(Win32Wifi, "WlanRegisterNotification") as m_reg, \
         patch.object(Win32Wifi, "WlanCloseHandle") as m_close:
        Win32Wifi.unregisterNotification(notification)
    assert not m_reg.called
    assert not m_close.called


def test_unregister_notification_thread_safe_under_concurrent_calls():
    """Two threads tearing down different notifications must not corrupt the
    shared bookkeeping lists."""
    handle_a = HANDLE(111)
    handle_b = HANDLE(222)
    cb_a, cb_b = object(), object()
    notif_a = Win32Wifi.NotificationObject(handle_a, cb_a)
    notif_b = Win32Wifi.NotificationObject(handle_b, cb_b)

    with Win32Wifi._notif_lock:
        Win32Wifi._notif_handles.extend([handle_a, handle_b])
        Win32Wifi._notif_callbacks.extend([cb_a, cb_b])

    barrier = threading.Barrier(2)

    def _runner(notif):
        barrier.wait()
        Win32Wifi.unregisterNotification(notif)

    with patch.object(Win32Wifi, "WlanRegisterNotification", return_value=None), \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0):
        t1 = threading.Thread(target=_runner, args=(notif_a,))
        t2 = threading.Thread(target=_runner, args=(notif_b,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    assert handle_a not in Win32Wifi._notif_handles
    assert handle_b not in Win32Wifi._notif_handles
    assert cb_a not in Win32Wifi._notif_callbacks
    assert cb_b not in Win32Wifi._notif_callbacks


def test_unregister_all_notifications_clears_state():
    handle_a = HANDLE(333)
    handle_b = HANDLE(444)
    with Win32Wifi._notif_lock:
        Win32Wifi._notif_handles.extend([handle_a, handle_b])
        Win32Wifi._notif_callbacks.extend([object(), object()])
    with patch.object(Win32Wifi, "WlanRegisterNotification", return_value=None) as m_reg, \
         patch.object(Win32Wifi, "WlanCloseHandle", return_value=0) as m_close:
        Win32Wifi.unregisterAllNotifications()
    assert m_reg.call_count == 2
    assert m_close.call_count == 2
    assert Win32Wifi._notif_handles == []
    assert Win32Wifi._notif_callbacks == []


# ---------------------------------------------------------------------------
# Malformed-XML profile parsing — should log debug, not raise
# ---------------------------------------------------------------------------

def test_wireless_profile_logs_debug_on_malformed_xml(caplog):
    profile_info = WLAN_PROFILE_INFO_LIST().ProfileInfo[0]
    profile_info.ProfileName = "Broken"
    profile_info.Flags = 0
    with caplog.at_level(logging.DEBUG, logger="win32wifi.Win32Wifi"):
        p = Win32Wifi.WirelessProfile(profile_info, "<not-actually-xml")
    assert p.ssid is None
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("malformed" in r.message.lower() or "parse" in r.message.lower() or
               "xml" in r.message.lower() for r in debug_records), \
        "Expected a debug log entry from _parse_xml on malformed XML"
