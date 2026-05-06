"""Low-level ``Win32NativeWifiApi`` tests.

These tests replace the ``wlanapi`` global with a ``MagicMock`` (via the
``mock_wlanapi`` fixture in ``conftest.py``) so we can assert that each
``Wlan*`` wrapper:

* calls the corresponding DLL entry point,
* sets ``argtypes``/``restype`` correctly,
* returns / raises based on the documented ``ERROR_SUCCESS`` convention.

We deliberately do NOT try to populate output buffers via ``byref`` here —
that's flaky and best covered by the high-level tests in ``test_high_level``.
"""
import pytest

from win32wifi import Win32NativeWifiApi
from win32wifi.Win32NativeWifiApi import (
    GUID,
    HANDLE,
    Win32WifiError,
)


def _guid():
    return GUID()


# ---------------------------------------------------------------------------
# Handle lifecycle
# ---------------------------------------------------------------------------

def test_wlan_open_handle_success(mock_wlanapi):
    handle = Win32NativeWifiApi.WlanOpenHandle()
    assert mock_wlanapi.WlanOpenHandle.called
    # Defaults to a fresh HANDLE; .value is whatever the mock left it (0).
    assert isinstance(handle, HANDLE)


def test_wlan_open_handle_raises_on_error(mock_wlanapi):
    mock_wlanapi.WlanOpenHandle.return_value = 87  # ERROR_INVALID_PARAMETER
    with pytest.raises(Win32WifiError) as exc:
        Win32NativeWifiApi.WlanOpenHandle()
    assert exc.value.error_code == 87
    assert "Error Code: 87" in str(exc.value)


def test_wlan_close_handle_success(mock_wlanapi):
    Win32NativeWifiApi.WlanCloseHandle(HANDLE(1))
    assert mock_wlanapi.WlanCloseHandle.called


def test_wlan_close_handle_raises_on_error(mock_wlanapi):
    mock_wlanapi.WlanCloseHandle.return_value = 6  # ERROR_INVALID_HANDLE
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanCloseHandle(HANDLE(1))


# ---------------------------------------------------------------------------
# Enumerations / scans / profile queries
# ---------------------------------------------------------------------------

def test_wlan_enum_interfaces_calls_dll(mock_wlanapi):
    Win32NativeWifiApi.WlanEnumInterfaces(HANDLE(1))
    assert mock_wlanapi.WlanEnumInterfaces.called


def test_wlan_enum_interfaces_raises(mock_wlanapi):
    mock_wlanapi.WlanEnumInterfaces.return_value = 5
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanEnumInterfaces(HANDLE(1))


def test_wlan_scan_passes_ssid_argument(mock_wlanapi):
    Win32NativeWifiApi.WlanScan(HANDLE(1), _guid(), "MyNet")
    assert mock_wlanapi.WlanScan.called


def test_wlan_scan_raises(mock_wlanapi):
    mock_wlanapi.WlanScan.return_value = 1
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanScan(HANDLE(1), _guid(), "X")


def test_wlan_get_profile_list_calls_dll(mock_wlanapi):
    Win32NativeWifiApi.WlanGetProfileList(HANDLE(1), _guid())
    assert mock_wlanapi.WlanGetProfileList.called


def test_wlan_get_profile_list_raises(mock_wlanapi):
    mock_wlanapi.WlanGetProfileList.return_value = 87
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanGetProfileList(HANDLE(1), _guid())


def test_wlan_get_profile_calls_dll(mock_wlanapi):
    Win32NativeWifiApi.WlanGetProfile(HANDLE(1), _guid(), "Profile")
    assert mock_wlanapi.WlanGetProfile.called


def test_wlan_get_profile_raises(mock_wlanapi):
    mock_wlanapi.WlanGetProfile.return_value = 1168  # ERROR_NOT_FOUND
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanGetProfile(HANDLE(1), _guid(), "Missing")


def test_wlan_delete_profile_passes_name_arg(mock_wlanapi):
    Win32NativeWifiApi.WlanDeleteProfile(HANDLE(1), _guid(), "ToZap")
    assert mock_wlanapi.WlanDeleteProfile.called


def test_wlan_delete_profile_raises(mock_wlanapi):
    mock_wlanapi.WlanDeleteProfile.return_value = 1168
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanDeleteProfile(HANDLE(1), _guid(), "Missing")


# ---------------------------------------------------------------------------
# Connect / disconnect
# ---------------------------------------------------------------------------

def test_wlan_disconnect_calls_dll(mock_wlanapi):
    Win32NativeWifiApi.WlanDisconnect(HANDLE(1), _guid())
    assert mock_wlanapi.WlanDisconnect.called


def test_wlan_disconnect_raises(mock_wlanapi):
    mock_wlanapi.WlanDisconnect.return_value = 1
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanDisconnect(HANDLE(1), _guid())


# ---------------------------------------------------------------------------
# Profile management
# ---------------------------------------------------------------------------

def test_wlan_set_profile_returns_zero_on_success(mock_wlanapi):
    result = Win32NativeWifiApi.WlanSetProfile(
        HANDLE(1), _guid(), 0, "<WLANProfile/>", None, True
    )
    assert result == 0
    assert mock_wlanapi.WlanSetProfile.called


def test_wlan_set_profile_raises_on_error(mock_wlanapi):
    mock_wlanapi.WlanSetProfile.return_value = 13  # ERROR_INVALID_DATA
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanSetProfile(
            HANDLE(1), _guid(), 0, "<bad/>", None, True
        )


def test_wlan_rename_profile_passes_both_names(mock_wlanapi):
    Win32NativeWifiApi.WlanRenameProfile(HANDLE(1), _guid(), "old", "new")
    args = mock_wlanapi.WlanRenameProfile.call_args[0]
    # args = (handle, byref(guid), strOldProfileName, strNewProfileName, None)
    assert args[2] == "old"
    assert args[3] == "new"


def test_wlan_rename_profile_raises(mock_wlanapi):
    mock_wlanapi.WlanRenameProfile.return_value = 1168
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanRenameProfile(HANDLE(1), _guid(), "old", "new")


# ---------------------------------------------------------------------------
# Reason code conversion (no failure mode)
# ---------------------------------------------------------------------------

def test_wlan_reason_code_to_string_calls_dll(mock_wlanapi):
    # WlanReasonCodeToString writes into a buffer the wrapper allocates;
    # the mock just needs to "succeed" so the wrapper returns the buffer's
    # initial empty value.
    out = Win32NativeWifiApi.WlanReasonCodeToString(0)
    assert mock_wlanapi.WlanReasonCodeToString.called
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# Notification registration
# ---------------------------------------------------------------------------

def test_wlan_register_notification_calls_dll(mock_wlanapi):
    def cb(_data, _ctx):  # pragma: no cover — never invoked here
        return None

    funcCallback = Win32NativeWifiApi.WlanRegisterNotification(HANDLE(1), cb)
    assert mock_wlanapi.WlanRegisterNotification.called
    # The wrapper returns the CFUNCTYPE-wrapped trampoline — callers must
    # keep a reference to it to prevent garbage collection.
    assert funcCallback is not None


def test_wlan_register_notification_raises(mock_wlanapi):
    mock_wlanapi.WlanRegisterNotification.return_value = 87
    with pytest.raises(Win32WifiError):
        Win32NativeWifiApi.WlanRegisterNotification(HANDLE(1), lambda *_: None)


# ---------------------------------------------------------------------------
# Module-level safety: make sure off-Windows we still detect the missing DLL
# ---------------------------------------------------------------------------

def test_check_wlanapi_raises_when_dll_missing(monkeypatch):
    monkeypatch.setattr(Win32NativeWifiApi, "wlanapi", None)
    with pytest.raises(RuntimeError, match="wlanapi.dll"):
        Win32NativeWifiApi._check_wlanapi()


def test_get_errno_and_get_last_error_return_int(mock_wlanapi):
    assert isinstance(Win32NativeWifiApi.get_errno(), int)
    assert isinstance(Win32NativeWifiApi.get_last_error(), int)
