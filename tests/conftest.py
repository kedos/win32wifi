"""Shared pytest fixtures for the win32wifi test suite."""
from unittest.mock import MagicMock

import pytest

from win32wifi import Win32NativeWifiApi


# Common Wlan* functions whose return value is checked against ERROR_SUCCESS.
# Default them to 0 so test setup is succinct; tests that exercise error paths
# override the relevant entry explicitly.
_DEFAULT_OK_FUNCS = (
    "WlanOpenHandle",
    "WlanCloseHandle",
    "WlanFreeMemory",
    "WlanEnumInterfaces",
    "WlanScan",
    "WlanGetNetworkBssList",
    "WlanGetAvailableNetworkList",
    "WlanGetProfileList",
    "WlanGetProfile",
    "WlanDeleteProfile",
    "WlanConnect",
    "WlanDisconnect",
    "WlanQueryInterface",
    "WlanSetProfile",
    "WlanReasonCodeToString",
    "WlanGetInterfaceCapability",
    "WlanGetFilterList",
    "WlanSetFilterList",
    "WlanQueryAutoConfigParameter",
    "WlanSetAutoConfigParameter",
    "WlanSaveTemporaryProfile",
    "WlanRenameProfile",
    "WlanSetProfileList",
    "WlanSetProfilePosition",
    "WlanSetInterface",
    "WlanRegisterNotification",
    "WlanRegisterVirtualStationNotification",
    "WlanGetSecuritySettings",
    "WlanSetSecuritySettings",
    "WlanGetProfileCustomUserData",
    "WlanSetProfileCustomUserData",
    "WlanHostedNetworkForceStart",
    "WlanHostedNetworkForceStop",
    "WlanHostedNetworkInitSettings",
    "WlanHostedNetworkQueryProperty",
    "WlanHostedNetworkQuerySecondaryKey",
    "WlanHostedNetworkQueryStatus",
    "WlanHostedNetworkRefreshSecuritySettings",
    "WlanHostedNetworkSetProperty",
    "WlanHostedNetworkSetSecondaryKey",
    "WlanHostedNetworkStartUsing",
    "WlanHostedNetworkStopUsing",
)


@pytest.fixture
def mock_wlanapi(monkeypatch):
    """Replace ``Win32NativeWifiApi.wlanapi`` with a ``MagicMock``.

    All known Wlan* DLL entry points default to returning ``0``
    (``ERROR_SUCCESS``) so that the bookkeeping code in our wrappers (handle
    cleanup, memory free, etc.) doesn't itself raise. Override
    ``mock_wlanapi.WlanXxx.return_value`` (or ``.side_effect``) per test.
    """
    fake = MagicMock(name="wlanapi")
    for name in _DEFAULT_OK_FUNCS:
        getattr(fake, name).return_value = 0
    monkeypatch.setattr(Win32NativeWifiApi, "wlanapi", fake)
    return fake
