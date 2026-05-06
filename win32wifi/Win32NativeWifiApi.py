# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - Shaked Gitelman
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

from ctypes import *
from enum import Enum
from typing import Optional, Any

from comtypes import GUID

from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPWSTR
from ctypes.wintypes import LPCWSTR


ERROR_SUCCESS = 0

class Win32WifiError(Exception):
    """Custom exception for Win32 Wifi API errors."""
    def __init__(self, message: str, error_code: int):
        super().__init__(f"{message} (Error Code: {error_code})")
        self.error_code = error_code

CLIENT_VERSION_WINDOWS_XP_SP3 = 1
CLIENT_VERSION_WINDOWS_VISTA_OR_LATER = 2

# Windot11.h defines
DOT11_SSID_MAX_LENGTH = 32
DOT11_BSSID_LIST_REVISION_1 = 1

# Ntddndis.h defines
NDIS_OBJECT_TYPE_DEFAULT = 0x80

# Load library only if on Windows
try:
    wlanapi = windll.LoadLibrary('wlanapi.dll')
except (NameError, OSError):
    wlanapi = None

# The WLAN_INTERFACE_STATE enumerated type indicates the state of an interface.
WLAN_INTERFACE_STATE = c_uint
WLAN_INTERFACE_STATE_DICT = {0: "wlan_interface_state_not_ready",
                             1: "wlan_interface_state_connected",
                             2: "wlan_interface_state_ad_hoc_network_formed",
                             3: "wlan_interface_state_disconnecting",
                             4: "wlan_interface_state_disconnected",
                             5: "wlan_interface_state_associating",
                             6: "wlan_interface_state_discovering",
                             7: "wlan_interface_state_authenticating"}

# The DOT11_MAC_ADDRESS types are used to define an IEEE media access control
# (MAC) address.
DOT11_MAC_ADDRESS = c_ubyte * 6

# The DOT11_BSS_TYPE enumerated type defines a basic service set (BSS) network
# type.
DOT11_BSS_TYPE = c_uint
DOT11_BSS_TYPE_DICT_KV = {
                           1: "dot11_BSS_type_infrastructure",
                           2: "dot11_BSS_type_independent",
                           3: "dot11_BSS_type_any"
                         }
DOT11_BSS_TYPE_DICT_VK = { v: k for k, v in DOT11_BSS_TYPE_DICT_KV.items() }

# The DOT11_PHY_TYPE enumeration defines an 802.11 PHY and media type.
DOT11_PHY_TYPE = c_uint
DOT11_PHY_TYPE_DICT = {0: "dot11_phy_type_unknown",
                       1: "dot11_phy_type_fhss",
                       2: "dot11_phy_type_dsss",
                       3: "dot11_phy_type_irbaseband",
                       4: "dot11_phy_type_ofdm",
                       5: "dot11_phy_type_hrdsss",
                       6: "dot11_phy_type_erp",
                       7: "dot11_phy_type_ht",
                       8: "dot11_phy_type_vht",
                       0x80000000: "dot11_phy_type_IHV_start",
                       0xffffffff: "dot11_phy_type_IHV_end"}

# The DOT11_AUTH_ALGORITHM enumerated type defines a wireless LAN
# authentication algorithm.
DOT11_AUTH_ALGORITHM_TYPE = c_uint
DOT11_AUTH_ALGORITHM_DICT = {1: "DOT11_AUTH_ALGO_80211_OPEN",
                             2: "DOT11_AUTH_ALGO_80211_SHARED_KEY",
                             3: "DOT11_AUTH_ALGO_WPA",
                             4: "DOT11_AUTH_ALGO_WPA_PSK",
                             5: "DOT11_AUTH_ALGO_WPA_NONE",
                             6: "DOT11_AUTH_ALGO_RSNA",
                             7: "DOT11_AUTH_ALGO_RSNA_PSK",
                             8: "DOT11_AUTH_ALGO_WPA3",
                             9: "DOT11_AUTH_ALGO_WPA3_SAE",
                             10: "DOT11_AUTH_ALGO_WPA3_OWE",
                             0x80000000: "DOT11_AUTH_ALGO_IHV_START",
                             0xffffffff: "DOT11_AUTH_ALGO_IHV_END"}

# The DOT11_CIPHER_ALGORITHM enumerated type defines a cipher algorithm for
# data encryption and decryption.
DOT11_CIPHER_ALGORITHM_TYPE = c_uint
DOT11_CIPHER_ALGORITHM_DICT = {0x00: "DOT11_CIPHER_ALGO_NONE",
                               0x01: "DOT11_CIPHER_ALGO_WEP40",
                               0x02: "DOT11_CIPHER_ALGO_TKIP",
                               0x04: "DOT11_CIPHER_ALGO_CCMP",
                               0x05: "DOT11_CIPHER_ALGO_WEP104",
                               0x06: "DOT11_CIPHER_ALGO_BIP",
                               0x07: "DOT11_CIPHER_ALGO_GCMP",
                               0x08: "DOT11_CIPHER_ALGO_GCMP_256",
                               0x100: "DOT11_CIPHER_ALGO_WPA_USE_GROUP",
                               0x100: "DOT11_CIPHER_ALGO_RSN_USE_GROUP",
                               0x101: "DOT11_CIPHER_ALGO_WEP",
                               0x80000000: "DOT11_CIPHER_ALGO_IHV_START",
                               0xffffffff: "DOT11_CIPHER_ALGO_IHV_END"}

DOT11_RADIO_STATE = c_uint
DOT11_RADIO_STATE_DICT = {0: "dot11_radio_state_unknown",
                          1: "dot11_radio_state_on",
                          2: "dot11_radio_state_off"}

WLAN_REASON_CODE = DWORD
WLAN_SIGNAL_QUALITY = c_ulong

WLAN_MAX_PHY_TYPE_NUMBER = 8

DOT11_RATE_SET_MAX_LENGTH = 126

# WLAN_AVAILABLE_NETWORK Flags
WLAN_AVAILABLE_NETWORK_CONNECTED = 0x00000001
WLAN_AVAILABLE_NETWORK_HAS_PROFILE = 0x00000002
WLAN_AVAILABLE_NETWORK_CONSOLE_USER_PROFILE = 0x00000004

WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES = 0x00000001
WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES = 0x00000002

# WLAN Profile Flags
WLAN_PROFILE_GROUP_POLICY = 0x00000001
WLAN_PROFILE_USER = 0x00000002
WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000004

# WLAN Notification Registration Flags
WLAN_NOTIFICATION_SOURCE_NONE = 0x0000
WLAN_NOTIFICATION_SOURCE_ONEX = 0x0004
WLAN_NOTIFICATION_SOURCE_ACM = 0x0008
WLAN_NOTIFICATION_SOURCE_MSM = 0x0010
WLAN_NOTIFICATION_SOURCE_SECURITY = 0x0020
WLAN_NOTIFICATION_SOURCE_IHV = 0x0040
WLAN_NOTIFICATION_SOURCE_HNWK = 0x0080
WLAN_NOTIFICATION_SOURCE_ALL = 0xffff

WLAN_NOTIFICATION_SOURCE_DICT = {
    WLAN_NOTIFICATION_SOURCE_NONE:      "WLAN_NOTIFICATION_SOURCE_NONE",
    WLAN_NOTIFICATION_SOURCE_ONEX:      "WLAN_NOTIFICATION_SOURCE_ONEX",
    WLAN_NOTIFICATION_SOURCE_ACM:       "WLAN_NOTIFICATION_SOURCE_ACM",
    WLAN_NOTIFICATION_SOURCE_MSM:       "WLAN_NOTIFICATION_SOURCE_MSM",
    WLAN_NOTIFICATION_SOURCE_SECURITY:  "WLAN_NOTIFICATION_SOURCE_SECURITY",
    WLAN_NOTIFICATION_SOURCE_IHV:       "WLAN_NOTIFICATION_SOURCE_IHV",
    WLAN_NOTIFICATION_SOURCE_HNWK:      "WLAN_NOTIFICATION_SOURCE_HNWK",
    WLAN_NOTIFICATION_SOURCE_ALL:       "WLAN_NOTIFICATION_SOURCE_ALL",
}


class ONEX_NOTIFICATION_TYPE_ENUM(Enum):
    OneXPublicNotificationBase          = 0
    OneXNotificationTypeResultUpdate    = 1
    OneXNotificationTypeAuthRestarted   = 2
    OneXNotificationTypeEventInvalid    = 3
    OneXNumNotifications                = OneXNotificationTypeEventInvalid


class WLAN_NOTIFICATION_ACM_ENUM(Enum):
    wlan_notification_acm_start                         = 0
    wlan_notification_acm_autoconf_enabled              = 1
    wlan_notification_acm_autoconf_disabled             = 2
    wlan_notification_acm_background_scan_enabled       = 3
    wlan_notification_acm_background_scan_disabled      = 4
    wlan_notification_acm_bss_type_change               = 5
    wlan_notification_acm_power_setting_change          = 6
    wlan_notification_acm_scan_complete                 = 7
    wlan_notification_acm_scan_fail                     = 8
    wlan_notification_acm_connection_start              = 9
    wlan_notification_acm_connection_complete           = 10
    wlan_notification_acm_connection_attempt_fail       = 11
    wlan_notification_acm_filter_list_change            = 12
    wlan_notification_acm_interface_arrival             = 13
    wlan_notification_acm_interface_removal             = 14
    wlan_notification_acm_profile_change                = 15
    wlan_notification_acm_profile_name_change           = 16
    wlan_notification_acm_profiles_exhausted            = 17
    wlan_notification_acm_network_not_available         = 18
    wlan_notification_acm_network_available             = 19
    wlan_notification_acm_disconnecting                 = 20
    wlan_notification_acm_disconnected                  = 21
    wlan_notification_acm_adhoc_network_state_change    = 22
    wlan_notification_acm_profile_unblocked             = 23
    wlan_notification_acm_screen_power_change           = 24
    wlan_notification_acm_profile_blocked               = 25
    wlan_notification_acm_scan_list_refresh             = 26
    wlan_notification_acm_end                           = 27


class WLAN_NOTIFICATION_MSM_ENUM(Enum):
    wlan_notification_msm_start                         = 0
    wlan_notification_msm_associating                   = 1 
    wlan_notification_msm_associated                    = 2
    wlan_notification_msm_authenticating                = 3
    wlan_notification_msm_connected                     = 4
    wlan_notification_msm_roaming_start                 = 5
    wlan_notification_msm_roaming_end                   = 6
    wlan_notification_msm_radio_state_change            = 7
    wlan_notification_msm_signal_quality_change         = 8
    wlan_notification_msm_disassociating                = 9
    wlan_notification_msm_disconnected                  = 10
    wlan_notification_msm_peer_join                     = 11
    wlan_notification_msm_peer_leave                    = 12
    wlan_notification_msm_adapter_removal               = 13
    wlan_notification_msm_adapter_operation_mode_change = 14
    wlan_notification_msm_end                           = 15


class WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM(Enum):
    wlan_hosted_network_state_change        = 4096
    wlan_hosted_network_peer_state_change   = 4097
    wlan_hosted_network_radio_state_change  = 4098


WLAN_CONNECTION_MODE = c_uint
WLAN_CONNECTION_MODE_KV = {0: "wlan_connection_mode_profile",
                           1: "wlan_connection_mode_temporary_profile",
                           2: "wlan_connection_mode_discovery_secure",
                           3: "wlan_connection_mode_discovery_unsecure",
                           4: "wlan_connection_mode_auto",
                           5: "wlan_connection_mode_invalid"}
WLAN_CONNECTION_MODE_VK = { v: k for k, v in WLAN_CONNECTION_MODE_KV.items() }

def _check_wlanapi():
    if wlanapi is None:
        raise RuntimeError("wlanapi.dll not loaded. This library requires Windows.")

class WLAN_INTERFACE_INFO(Structure):
    """
        The WLAN_INTERFACE_INFO structure contains information about a wireless
        LAN interface.

        typedef struct _WLAN_INTERFACE_INFO {
            GUID                 InterfaceGuid;
            WCHAR                strInterfaceDescription[256];
            WLAN_INTERFACE_STATE isState;
        } WLAN_INTERFACE_INFO, *PWLAN_INTERFACE_INFO;
    """
    _fields_ = [("InterfaceGuid", GUID),
                ("strInterfaceDescription", c_wchar * 256),
                ("isState", WLAN_INTERFACE_STATE)]


class WLAN_INTERFACE_INFO_LIST(Structure):
    """
        The WLAN_INTERFACE_INFO_LIST structure contains an array of NIC
        interface information.

        typedef struct _WLAN_INTERFACE_INFO_LIST {
            DWORD               dwNumberOfItems;
            DWORD               dwIndex;
            WLAN_INTERFACE_INFO InterfaceInfo[];
        } WLAN_INTERFACE_INFO_LIST, *PWLAN_INTERFACE_INFO_LIST;
    """
    _fields_ = [("NumberOfItems", DWORD),
                ("Index", DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class WLAN_PHY_RADIO_STATE(Structure):
    """
    """
    _fields_ = [("dwPhyIndex", DWORD),
                ("dot11SoftwareRadioState", DOT11_RADIO_STATE),
                ("dot11HardwareRadioState", DOT11_RADIO_STATE)]


class WLAN_RADIO_STATE(Structure):
    """
        The WLAN_RADIO_STATE structure specifies the radio state on a list
        of physical layer (PHY) types.

        typedef struct _WLAN_RADIO_STATE {
            DWORD                dwNumberOfPhys;
            WLAN_PHY_RADIO_STATE PhyRadioState[64];
        } WLAN_RADIO_STATE, *PWLAN_RADIO_STATE
    """
    _fields_ = [("dwNumberOfPhys", DWORD),
                ("PhyRadioState", WLAN_PHY_RADIO_STATE * 64)]

class DOT11_SSID(Structure):
    """
        A DOT11_SSID structure contains the SSID of an interface.

        typedef struct _DOT11_SSID {
            ULONG uSSIDLength;
            UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
        } DOT11_SSID, *PDOT11_SSID;
    """
    _fields_ = [("SSIDLength", c_ulong),
                ("SSID", c_char * DOT11_SSID_MAX_LENGTH)]


class WLAN_RAW_DATA(Structure):
    """
        The WLAN_RAW_DATA structure contains raw data in the form of a blob
        that is used by some Native Wifi functions.

        typedef struct _WLAN_RAW_DATA {
            DWORD dwDataSize;
            BYTE  DataBlob[1];
        } WLAN_RAW_DATA, *PWLAN_RAW_DATA;
    """
    _fields_ = [("DataSize", DWORD),
                ("DataBlob", c_byte * 1)]


class WLAN_RATE_SET(Structure):
    """
        typedef struct _WLAN_RATE_SET {
            ULONG  uRateSetLength;
            USHORT usRateSet[DOT11_RATE_SET_MAX_LENGTH];
        } WLAN_RATE_SET, *PWLAN_RATE_SET;
    """
    _fields_ = [("RateSetLength", c_ulong),
                ("RateSet", c_ushort * DOT11_RATE_SET_MAX_LENGTH)]


class WLAN_BSS_ENTRY(Structure):
    """
        The WLAN_BSS_ENTRY structure contains information about a basic service
        set (BSS).

        typedef struct _WLAN_BSS_ENTRY {
            DOT11_SSID        dot11Ssid;
            ULONG             uPhyId;
            DOT11_MAC_ADDRESS dot11Bssid;
            DOT11_BSS_TYPE    dot11BssType;
            DOT11_PHY_TYPE    dot11BssPhyType;
            LONG              lRssi;
            ULONG             uLinkQuality;
            BOOLEAN           bInRegDomain;
            USHORT            usBeaconPeriod;
            ULONGLONG         ullTimestamp;
            ULONGLONG         ullHostTimestamp;
            USHORT            usCapabilityInformation;
            ULONG             ulChCenterFrequency;
            WLAN_RATE_SET     wlanRateSet;
            ULONG             ulIeOffset;
            ULONG             ulIeSize;
        } WLAN_BSS_ENTRY, *PWLAN_BSS_ENTRY;
    """
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("PhyId", c_ulong),
                ("dot11Bssid", DOT11_MAC_ADDRESS),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("dot11BssPhyType", DOT11_PHY_TYPE),
                ("Rssi", c_long),
                ("LinkQuality", c_ulong),
                ("InRegDomain", BOOL),
                ("BeaconPeriod", c_ushort),
                ("Timestamp", c_ulonglong),
                ("HostTimestamp", c_ulonglong),
                ("CapabilityInformation", c_ushort),
                ("ChCenterFrequency", c_ulong),
                ("wlanRateSet", WLAN_RATE_SET),
                ("IeOffset", c_ulong),
                ("IeSize", c_ulong)]


class WLAN_BSS_LIST(Structure):
    """
        The WLAN_BSS_LIST structure contains a list of basic service set (BSS)
        entries.

        typedef struct _WLAN_BSS_LIST {
            DWORD          dwTotalSize;
            DWORD          dwNumberOfItems;
            WLAN_BSS_ENTRY wlanBssEntries[1];
        } WLAN_BSS_LIST, *PWLAN_BSS_LIST;
    """
    _fields_ = [("TotalSize", DWORD),
                ("NumberOfItems", DWORD),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_AVAILABLE_NETWORK(Structure):
    """
        The WLAN_AVAILABLE_NETWORK structure contains information about an
        available wireless network.

        typedef struct _WLAN_AVAILABLE_NETWORK {
            WCHAR                  strProfileName[256];
            DOT11_SSID             dot11Ssid;
            DOT11_BSS_TYPE         dot11BssType;
            ULONG                  uNumberOfBssids;
            BOOL                   bNetworkConnectable;
            WLAN_REASON_CODE       wlanNotConnectableReason;
            ULONG                  uNumberOfPhyTypes;
            DOT11_PHY_TYPE         dot11PhyTypes[WLAN_MAX_PHY_TYPE_NUMBER];
            BOOL                   bMorePhyTypes;
            WLAN_SIGNAL_QUALITY    wlanSignalQuality;
            BOOL                   bSecurityEnabled;
            DOT11_AUTH_ALGORITHM   dot11DefaultAuthAlgorithm;
            DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
            DWORD                  dwFlags;
            DWORD                  dwReserved;
        } WLAN_AVAILABLE_NETWORK, *PWLAN_AVAILABLE_NETWORK;
    """
    _fields_ = [("ProfileName", c_wchar * 256),
                ("dot11Ssid", DOT11_SSID),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("NumberOfBssids", c_ulong),
                ("NetworkConnectable", BOOL),
                ("wlanNotConnectableReason", WLAN_REASON_CODE),
                ("NumberOfPhyTypes", c_ulong),
                ("dot11PhyTypes", DOT11_PHY_TYPE * WLAN_MAX_PHY_TYPE_NUMBER),
                ("MorePhyTypes", BOOL),
                ("wlanSignalQuality", WLAN_SIGNAL_QUALITY),
                ("SecurityEnabled", BOOL),
                ("dot11DefaultAuthAlgorithm", DOT11_AUTH_ALGORITHM_TYPE),
                ("dot11DefaultCipherAlgorithm", DOT11_CIPHER_ALGORITHM_TYPE),
                ("Flags", DWORD),
                ("Reserved", DWORD)]


class WLAN_AVAILABLE_NETWORK_LIST(Structure):
    """
        The WLAN_AVAILABLE_NETWORK_LIST structure contains an array of
        information about available networks.

        typedef struct _WLAN_AVAILABLE_NETWORK_LIST {
            DWORD                  dwNumberOfItems;
            DWORD                  dwIndex;
            WLAN_AVAILABLE_NETWORK Network[1];
        } WLAN_AVAILABLE_NETWORK_LIST, *PWLAN_AVAILABLE_NETWORK_LIST;
    """
    _fields_ = [("NumberOfItems", DWORD),
                ("Index", DWORD),
                ("Network", WLAN_AVAILABLE_NETWORK * 1)]


class WLAN_PROFILE_INFO(Structure):
    """
        The WLAN_PROFILE_INFO structure contains basic information about a
        profile.

        typedef struct _WLAN_PROFILE_INFO {
            WCHAR strProfileName[256];
            DWORD dwFlags;
        } WLAN_PROFILE_INFO, *PWLAN_PROFILE_INFO;
    """
    _fields_ = [("ProfileName", c_wchar * 256),
                ("Flags", DWORD)]


class WLAN_PROFILE_INFO_LIST(Structure):
    """
        The WLAN_PROFILE_INFO_LIST structure contains a list of wireless
        profile information.

        typedef struct _WLAN_PROFILE_INFO_LIST {
            DWORD             dwNumberOfItems;
            DWORD             dwIndex;
            WLAN_PROFILE_INFO ProfileInfo[1];
        } WLAN_PROFILE_INFO_LIST, *PWLAN_PROFILE_INFO_LIST;
    """
    _fields_ = [("NumberOfItems", DWORD),
                ("Index", DWORD),
                ("ProfileInfo", WLAN_PROFILE_INFO * 1)]


class WLAN_NOTIFICATION_DATA(Structure):
    """
        The WLAN_NOTIFICATION_DATA structure contains information provided 
        when receiving notifications.

        typedef struct _WLAN_NOTIFICATION_DATA {
          DWORD NotificationSource;
          DWORD NotificationCode;
          GUID  InterfaceGuid;
          DWORD dwDataSize;
          PVOID pData;
        } WLAN_NOTIFICATION_DATA, *PWLAN_NOTIFICATION_DATA;
    """ 
    _fields_ = [("NotificationSource", DWORD),
                ("NotificationCode", DWORD),
                ("InterfaceGuid", GUID),
                ("dwDataSize", DWORD),
                ("pData", c_void_p)]


class WLAN_NOTIFICATION_CALLBACK():
    """
        The WLAN_NOTIFICATION_CALLBACK allback function prototype defines 
        the type of notification callback function.

        typedef VOID ( WINAPI *WLAN_NOTIFICATION_CALLBACK)(
           PWLAN_NOTIFICATION_DATA data,
           PVOID                   context
        );
    """
    _fields_ = [("data", POINTER(WLAN_NOTIFICATION_DATA)),
                ("context", c_void_p)]


class WLAN_MSM_NOTIFICATION_DATA(Structure):
    """
    typedef struct _WLAN_MSM_NOTIFICATION_DATA {
        WLAN_CONNECTION_MODE wlanConnectionMode;
        WCHAR                strProfileName[WLAN_MAX_NAME_LENGTH];
        DOT11_SSID           dot11Ssid;
        DOT11_BSS_TYPE       dot11BssType;
        DOT11_MAC_ADDRESS    dot11MacAddr;
        BOOL                 bSecurityEnabled;
        BOOL                 bFirstPeer;
        BOOL                 bLastPeer;
        WLAN_REASON_CODE     wlanReasonCode;
    } WLAN_MSM_NOTIFICATION_DATA, *PWLAN_MSM_NOTIFICATION_DATA;
    """
    _fields_ = [("wlanConnectionMode", WLAN_CONNECTION_MODE),
                ("strProfileName", c_wchar * 256),
                ("dot11Ssid", DOT11_SSID),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("dot11MacAddr", DOT11_MAC_ADDRESS),
                ("bSecurityEnabled", BOOL),
                ("bFirstPeer", BOOL),
                ("bLastPeer", BOOL),
                ("wlanReasonCode", WLAN_REASON_CODE),]


WLAN_NOTIFICATION_DATA_MSM_TYPES_DICT = {
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_associating: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_associated: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_authenticating: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_connected: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_roaming_start: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_roaming_end: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_radio_state_change: None,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_signal_quality_change: c_ulong,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_disassociating: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_disconnected: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_peer_join: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_peer_leave: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_adapter_removal: WLAN_MSM_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_MSM_ENUM.wlan_notification_msm_adapter_operation_mode_change: c_ulong,
}

class WLAN_CONNECTION_NOTIFICATION_DATA(Structure):
    """
    typedef struct _WLAN_CONNECTION_NOTIFICATION_DATA {
        WLAN_CONNECTION_MODE wlanConnectionMode;
        WCHAR                strProfileName[WLAN_MAX_NAME_LENGTH];
        DOT11_SSID           dot11Ssid;
        DOT11_BSS_TYPE       dot11BssType;
        BOOL                 bSecurityEnabled;
        WLAN_REASON_CODE     wlanReasonCode;
        DWORD                dwFlags;
        WCHAR                strProfileXml[1];
    } WLAN_CONNECTION_NOTIFICATION_DATA, *PWLAN_CONNECTION_NOTIFICATION_DATA;
    """
    _fields_ = [("wlanConnectionMode", WLAN_CONNECTION_MODE),
                ("strProfileName", c_wchar * 256),
                ("dot11Ssid", DOT11_SSID),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("bSecurityEnabled", BOOL),
                ("wlanReasonCode", WLAN_REASON_CODE),
                ("dwFlags", DWORD),
                ("strProfileXml", (c_wchar * 1)),]


WLAN_NOTIFICATION_DATA_ACM_TYPES_DICT = {
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_autoconf_enabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_autoconf_disabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_background_scan_enabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_background_scan_disabled: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_bss_type_change: DOT11_BSS_TYPE,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_power_setting_change: None,  # TODO: Change to WLAN_POWER_SETTING
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_scan_complete: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_scan_fail: WLAN_REASON_CODE,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_connection_start: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_connection_complete: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_connection_attempt_fail: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_filter_list_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_interface_arrival: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_interface_removal: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_profile_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_profile_name_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_profiles_exhausted: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_network_not_available: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_network_available: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_disconnecting: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_disconnected: WLAN_CONNECTION_NOTIFICATION_DATA,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_adhoc_network_state_change: None,  # TODO: Change to WLAN_ADHOC_NETWORK_STATE
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_profile_unblocked: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_screen_power_change: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_profile_blocked: None,
    WLAN_NOTIFICATION_ACM_ENUM.wlan_notification_acm_scan_list_refresh: None,
}

def WlanRegisterNotification(hClientHandle, callback, pCallbackContext=None):
    """
        The WlanRegisterNotification function is used to register and 
        unregister notifications on all wireless interfaces.

        DWORD WINAPI WlanRegisterNotification(
          _In_       HANDLE                      hClientHandle,
          _In_       DWORD                       dwNotifSource,
          _In_       BOOL                        bIgnoreDuplicate,
          _In_opt_   WLAN_NOTIFICATION_CALLBACK  funcCallback,
          _In_opt_   PVOID                       pCallbackContext,
          _Reserved_ PVOID                       pReserved,
          _Out_opt_  PDWORD                      pdwPrevNotifSource
        );
    """
    _check_wlanapi()
    WLAN_NOTIFICATION_CALLBACK_M = CFUNCTYPE(None,  # type for return value
                                             POINTER(WLAN_NOTIFICATION_DATA),
                                             c_void_p,
                                             use_last_error=True)

    func_ref = wlanapi.WlanRegisterNotification
    func_ref.argtypes = [
        HANDLE, 
        DWORD,
        BOOL,
        WLAN_NOTIFICATION_CALLBACK_M,
        c_void_p,
        c_void_p,
        POINTER(DWORD)]
    func_ref.restype = DWORD

    dwNotifSource = WLAN_NOTIFICATION_SOURCE_ALL
    bIgnoreDuplicate = True
    funcCallback = WLAN_NOTIFICATION_CALLBACK_M(callback)
    pdwPrevNotifSource = None

    result = func_ref(hClientHandle,
                      dwNotifSource, 
                      bIgnoreDuplicate, 
                      funcCallback, 
                      pCallbackContext, 
                      None, 
                      pdwPrevNotifSource)

    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanRegisterNotification failed", result)
    return funcCallback


def WlanOpenHandle() -> HANDLE:
    """
        The WlanOpenHandle function opens a connection to the server.

        DWORD WINAPI WlanOpenHandle(
            _In_        DWORD dwClientVersion,
            _Reserved_  PVOID pReserved,
            _Out_       PDWORD pdwNegotiatedVersion,
            _Out_       PHANDLE phClientHandle
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanOpenHandle
    func_ref.argtypes = [DWORD, c_void_p, POINTER(DWORD), POINTER(HANDLE)]
    func_ref.restype = DWORD
    negotiated_version = DWORD()
    client_handle = HANDLE()
    result = func_ref(2, None, byref(negotiated_version), byref(client_handle))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanOpenHandle failed", result)
    return client_handle


def WlanCloseHandle(hClientHandle: HANDLE) -> int:
    """
        The WlanCloseHandle function closes a connection to the server.

        DWORD WINAPI WlanCloseHandle(
            _In_        HANDLE hClientHandle,
            _Reserved_  PVOID pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanCloseHandle
    func_ref.argtypes = [HANDLE, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanCloseHandle failed", result)
    return result


def WlanFreeMemory(pMemory: c_void_p) -> None:
    """
        The WlanFreeMemory function frees memory. Any memory returned from
        Native Wifi functions must be freed.

        VOID WINAPI WlanFreeMemory(
            _In_  PVOID pMemory
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanFreeMemory
    func_ref.argtypes = [c_void_p]
    func_ref(pMemory)


def WlanEnumInterfaces(hClientHandle: HANDLE) -> POINTER(WLAN_INTERFACE_INFO_LIST):
    """
        The WlanEnumInterfaces function enumerates all of the wireless LAN
        interfaces currently enabled on the local computer.

        DWORD WINAPI WlanEnumInterfaces(
            _In_        HANDLE hClientHandle,
            _Reserved_  PVOID pReserved,
            _Out_       PWLAN_INTERFACE_INFO_LIST *ppInterfaceList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanEnumInterfaces
    func_ref.argtypes = [HANDLE,
                         c_void_p,
                         POINTER(POINTER(WLAN_INTERFACE_INFO_LIST))]
    func_ref.restype = DWORD
    wlan_ifaces = pointer(WLAN_INTERFACE_INFO_LIST())
    result = func_ref(hClientHandle, None, byref(wlan_ifaces))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanEnumInterfaces failed", result)
    return wlan_ifaces


def WlanScan(hClientHandle: HANDLE, pInterfaceGuid: GUID, ssid: str = "") -> int:
    """
        The WlanScan function requests a scan for available networks on the
        indicated interface.

        DWORD WINAPI WlanScan(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _In_opt_    const PDOT11_SSID pDot11Ssid,
            _In_opt_    const PWLAN_RAW_DATA pIeData,
            _Reserved_  PVOID pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanScan
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         POINTER(DOT11_SSID),
                         POINTER(WLAN_RAW_DATA),
                         c_void_p]
    func_ref.restype = DWORD
    if ssid:
        ssid_bytes = ssid.encode('utf-8')
        length = len(ssid_bytes)
        if length > DOT11_SSID_MAX_LENGTH:
            raise Win32WifiError(f"SSIDs have a maximum length of {DOT11_SSID_MAX_LENGTH} characters.", length)
        dot11_ssid = byref(DOT11_SSID(length, ssid_bytes))
    else:
        dot11_ssid = None
    # TODO: Support WLAN_RAW_DATA argument.
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      dot11_ssid,
                      None,
                      None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanScan failed", result)
    return result


def WlanGetNetworkBssList(hClientHandle: HANDLE, pInterfaceGuid: GUID) -> POINTER(WLAN_BSS_LIST):
    """
        The WlanGetNetworkBssList function retrieves a list of the basic
        service set (BSS) entries of the wireless network or networks on a
        given wireless LAN interface.

        DWORD WINAPI WlanGetNetworkBssList(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _In_        const  PDOT11_SSID pDot11Ssid,
            _In_        DOT11_BSS_TYPE dot11BssType,
            _In_        BOOL bSecurityEnabled,
            _Reserved_  PVOID pReserved,
            _Out_       PWLAN_BSS_LIST *ppWlanBssList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetNetworkBssList
    # TODO: handle the arguments descibed below.
    # pDot11Ssid - When set to NULL, the returned list contains all of
    # available BSS entries on a wireless LAN interface.
    # dot11BssType - The BSS type of the network. This parameter is ignored if
    # the SSID of the network for the BSS list is unspecified (the pDot11Ssid
    # parameter is NULL).
    # bSecurityEnabled - A value that indicates whether security is enabled on
    # the network. This parameter is only valid when the SSID of the network
    # for the BSS list is specified (the pDot11Ssid parameter is not NULL).
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         c_void_p,
                         c_void_p,
                         c_void_p,
                         c_void_p,
                         POINTER(POINTER(WLAN_BSS_LIST))]
    func_ref.restype = DWORD
    wlan_bss_list = pointer(WLAN_BSS_LIST())
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      None,
                      None,
                      None,
                      None,
                      byref(wlan_bss_list))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetNetworkBssList failed", result)
    return wlan_bss_list


def WlanGetAvailableNetworkList(hClientHandle: HANDLE, pInterfaceGuid: GUID) -> POINTER(WLAN_AVAILABLE_NETWORK_LIST):
    """
        The WlanGetAvailableNetworkList function retrieves the list of
        available networks on a wireless LAN interface.

        DWORD WINAPI WlanGetAvailableNetworkList(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _In_        DWORD dwFlags,
            _Reserved_  PVOID pReserved,
            _Out_       PWLAN_AVAILABLE_NETWORK_LIST *ppAvailableNetworkList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetAvailableNetworkList
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         DWORD,
                         c_void_p,
                         POINTER(POINTER(WLAN_AVAILABLE_NETWORK_LIST))]
    func_ref.restype = DWORD
    wlan_available_network_list = pointer(WLAN_AVAILABLE_NETWORK_LIST())
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      0,
                      None,
                      byref(wlan_available_network_list))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetAvailableNetworkList failed", result)
    return wlan_available_network_list


def WlanGetProfileList(hClientHandle: HANDLE, pInterfaceGuid: GUID) -> POINTER(WLAN_PROFILE_INFO_LIST):
    """
        The WlanGetProfileList function retrieves the list of profiles in
        preference order.

        DWORD WINAPI WlanGetProfileList(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _Reserved_  PVOID pReserved,
            _Out_       PWLAN_PROFILE_INFO_LIST *ppProfileList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetProfileList
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         c_void_p,
                         POINTER(POINTER(WLAN_PROFILE_INFO_LIST))]
    func_ref.restype = DWORD
    wlan_profile_info_list = pointer(WLAN_PROFILE_INFO_LIST())
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      None,
                      byref(wlan_profile_info_list))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetProfileList failed", result)
    return wlan_profile_info_list


def WlanGetProfile(hClientHandle: HANDLE, pInterfaceGuid: GUID, profileName: str) -> LPWSTR:
    """
        The WlanGetProfile function retrieves all information about a specified
        wireless profile.

        DWORD WINAPI WlanGetProfile(
            _In_         HANDLE hClientHandle,
            _In_         const GUID *pInterfaceGuid,
            _In_         LPCWSTR strProfileName,
            _Reserved_   PVOID pReserved,
            _Out_        LPWSTR *pstrProfileXml,
            _Inout_opt_  DWORD *pdwFlags,
            _Out_opt_    PDWORD pdwGrantedAccess
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetProfile
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         LPCWSTR,
                         c_void_p,
                         POINTER(LPWSTR),
                         POINTER(DWORD),
                         POINTER(DWORD)]
    func_ref.restype = DWORD
    pdw_granted_access = DWORD()
    xml = LPWSTR()
    flags = DWORD(WLAN_PROFILE_GET_PLAINTEXT_KEY)
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      profileName,
                      None,
                      byref(xml),
                      byref(flags),
                      byref(pdw_granted_access))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetProfile failed", result)
    return xml

def WlanDeleteProfile(hClientHandle: HANDLE, pInterfaceGuid: GUID, profileName: str) -> int:
    """
    DWORD WINAPI WlanDeleteProfile(
        _In_             HANDLE  hClientHandle,
        _In_       const GUID    *pInterfaceGuid,
        _In_             LPCWSTR strProfileName,
        _Reserved_       PVOID   pReserved
    );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanDeleteProfile
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         LPCWSTR,
                         c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      profileName,
                      None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanDeleteProfile failed for profile {profileName}", result)
    return result


class NDIS_OBJECT_HEADER(Structure):
    """
        The NDIS_OBJECT_HEADER structure packages the object type, version, and
        size information that is required in many NDIS 6.0 structures.

        typedef struct _NDIS_OBJECT_HEADER {
          UCHAR  Type;
          UCHAR  Revision;
          USHORT Size;
        } NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;
    """
    _fields_ = [("Type", c_char),
                ("Revision", c_char),
                ("Size", c_ushort)]

class DOT11_BSSID_LIST(Structure):
    """
        The DOT11_BSSID_LIST structure contains a list of basic service set
        (BSS) identifiers.

        typedef struct _DOT11_BSSID_LIST {
          NDIS_OBJECT_HEADER Header;
          ULONG              uNumOfEntries;
          ULONG              uTotalNumOfEntries;
          DOT11_MAC_ADDRESS  BSSIDs[1];
        } DOT11_BSSID_LIST, *PDOT11_BSSID_LIST;
    """
    #NOTE: Would benefit from dynamic instantiation to mod # of BSSIDs
    _fields_ = [("Header", NDIS_OBJECT_HEADER),
                ("uNumOfEntries", c_ulong),
                ("uTotalNumOfEntries", c_ulong),
                ("BSSIDs", DOT11_MAC_ADDRESS * 1)]

class WLAN_CONNECTION_PARAMETERS(Structure):
    """
        The WLAN_CONNECTION_PARAMETERS structure specifies the parameters used
        when using the WlanConnect function.

        typedef struct _WLAN_CONNECTION_PARAMETERS {
          WLAN_CONNECTION_MODE wlanConnectionMode;
          LPCWSTR              strProfile;
          PDOT11_SSID          pDot11Ssid;
          PDOT11_BSSID_LIST    pDesiredBssidList;
          DOT11_BSS_TYPE       dot11BssType;
          DWORD                dwFlags;
        } WLAN_CONNECTION_PARAMETERS, *PWLAN_CONNECTION_PARAMETERS;
    """
    """
        Re strProfile:
        If wlanConnectionMode is set to wlan_connection_mode_profile, then
        strProfile specifies the name of the profile used for the connection.
        If wlanConnectionMode is set to wlan_connection_mode_temporary_profile,
        then strProfile specifies the XML representation of the profile used for
        the connection. If wlanConnectionMode is set to
        wlan_connection_mode_discovery_secure or wlan_connection_mode_discovery_unsecure,
        then strProfile should be set to NULL.

        NOTE: For now, only profile names will be accepted, per strProfileName
        elsewhere.
    """
    _fields_ = [("wlanConnectionMode", WLAN_CONNECTION_MODE),
                ("strProfile", LPCWSTR),
                ("pDot11_ssid", POINTER(DOT11_SSID)),
                ("pDesiredBssidList", POINTER(DOT11_BSSID_LIST)),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("dwFlags", DWORD)]

def WlanConnect(hClientHandle: HANDLE, pInterfaceGuid: GUID, pConnectionParameters: WLAN_CONNECTION_PARAMETERS) -> int:
    """
    The WlanConnect function attempts to connect to a specific network.

    DWORD WINAPI WlanConnect(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _In_        const PWLAN_CONNECTION_PARAMETERS pConnectionParameters,
            _Reserved_  PVOID pReserved
    );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanConnect
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         POINTER(WLAN_CONNECTION_PARAMETERS),
                         c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle,
                      pointer(pInterfaceGuid),
                      pointer(pConnectionParameters),
                      None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanConnect failed", result)
    return result

def WlanDisconnect(hClientHandle: HANDLE, pInterfaceGuid: GUID) -> int:
    """
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanDisconnect
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanDisconnect failed", result)
    return result

WLAN_INTF_OPCODE = c_uint
WLAN_INTF_OPCODE_DICT = {
    0x000000000: "wlan_intf_opcode_autoconf_start",
    1: "wlan_intf_opcode_autoconf_enabled",
    2: "wlan_intf_opcode_background_scan_enabled",
    3: "wlan_intf_opcode_media_streaming_mode",
    4: "wlan_intf_opcode_radio_state",
    5: "wlan_intf_opcode_bss_type",
    6: "wlan_intf_opcode_interface_state",
    7: "wlan_intf_opcode_current_connection",
    8: "wlan_intf_opcode_channel_number",
    9: "wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs",
    10: "wlan_intf_opcode_supported_adhoc_auth_cipher_pairs",
    11: "wlan_intf_opcode_supported_country_or_region_string_list",
    12: "wlan_intf_opcode_current_operation_mode",
    13: "wlan_intf_opcode_supported_safe_mode",
    14: "wlan_intf_opcode_certified_safe_mode",
    15: "wlan_intf_opcode_hosted_network_capable",
    16: "wlan_intf_opcode_management_frame_protection_capable",
    0x0fffffff: "wlan_intf_opcode_autoconf_end",
    0x10000100: "wlan_intf_opcode_msm_start",
    17: "wlan_intf_opcode_statistics",
    18: "wlan_intf_opcode_rssi",
    0x1fffffff: "wlan_intf_opcode_msm_end",
    0x20010000: "wlan_intf_opcode_security_start",
    0x2fffffff: "wlan_intf_opcode_security_end",
    0x30000000: "wlan_intf_opcode_ihv_start",
    0x3fffffff: "wlan_intf_opcode_ihv_end"
}

WLAN_OPCODE_VALUE_TYPE = c_uint
WLAN_OPCODE_VALUE_TYPE_DICT = {
    0: "wlan_opcode_value_type_query_only",
    1: "wlan_opcode_value_type_set_by_group_policy",
    2: "wlan_opcode_value_type_set_by_user",
    3: "wlan_opcode_value_type_invalid"
}

class WLAN_ASSOCIATION_ATTRIBUTES(Structure):
    """
    """
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("dot11Bssid", DOT11_MAC_ADDRESS),
                ("dot11PhyType", DOT11_PHY_TYPE),
                ("uDot11PhyIndex", c_ulong),
                ("wlanSignalQuality", WLAN_SIGNAL_QUALITY),
                ("ulRxRate", c_ulong),
                ("ulTxRate", c_ulong)]

class WLAN_SECURITY_ATTRIBUTES(Structure):
    """
    """
    _fields_ = [("bSecurityEnabled", BOOL),
                ("bOneXEnabled", BOOL),
                ("dot11AuthAlgorithm", DOT11_AUTH_ALGORITHM_TYPE),
                ("dot11CipherAlgorithm", DOT11_CIPHER_ALGORITHM_TYPE)]

class WLAN_CONNECTION_ATTRIBUTES(Structure):
    """
        The WlanQueryInterface function queries various parameters of a
        specified interface.

        typedef struct _WLAN_CONNECTION_ATTRIBUTES {
          WLAN_INTERFACE_STATE        isState;
          WLAN_CONNECTION_MODE        wlanConnectionMode;
          WCHAR                       strProfileName[256];
          WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
          WLAN_SECURITY_ATTRIBUTES    wlanSecurityAttributes;
        } WLAN_CONNECTION_ATTRIBUTES, *PWLAN_CONNECTION_ATTRIBUTES;
    """
    _fields_ = [("isState", WLAN_INTERFACE_STATE),
                ("wlanConnectionMode", WLAN_CONNECTION_MODE),
                ("strProfileName", c_wchar * 256),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
                ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]

WLAN_INTF_OPCODE_TYPE_DICT = {
    "wlan_intf_opcode_autoconf_enabled": c_bool,
    "wlan_intf_opcode_background_scan_enabled": c_bool,
    "wlan_intf_opcode_radio_state": WLAN_RADIO_STATE,
    "wlan_intf_opcode_bss_type": DOT11_BSS_TYPE,
    "wlan_intf_opcode_interface_state": WLAN_INTERFACE_STATE,
    "wlan_intf_opcode_current_connection": WLAN_CONNECTION_ATTRIBUTES,
    "wlan_intf_opcode_channel_number": c_ulong,
    #"wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs": \
            #WLAN_AUTH_CIPHER_PAIR_LIST,
    #"wlan_intf_opcode_supported_adhoc_auth_cipher_pairs": \
            #WLAN_AUTH_CIPHER_PAIR_LIST,
    #"wlan_intf_opcode_supported_country_or_region_string_list": \
            #WLAN_COUNTRY_OR_REGION_STRING_LIST,
    "wlan_intf_opcode_media_streaming_mode": c_bool,
    #"wlan_intf_opcode_statistics": WLAN_STATISTICS,
    "wlan_intf_opcode_rssi": c_long,
    "wlan_intf_opcode_current_operation_mode": c_ulong,
    "wlan_intf_opcode_supported_safe_mode": c_bool,
    "wlan_intf_opcode_certified_safe_mode": c_bool
}

def WlanQueryInterface(hClientHandle: HANDLE, pInterfaceGuid: GUID, OpCode: WLAN_INTF_OPCODE) -> POINTER(Any):
    """
        DWORD WINAPI WlanQueryInterface(
          _In_        HANDLE hClientHandle,
          _In_        const GUID *pInterfaceGuid,
          _In_        WLAN_INTF_OPCODE OpCode,
          _Reserved_  PVOID pReserved,
          _Out_       PDWORD pdwDataSize,
          _Out_       PVOID *ppData,
          _Out_opt_   PWLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanQueryInterface
    opcode_name = WLAN_INTF_OPCODE_DICT[OpCode.value]
    return_type = WLAN_INTF_OPCODE_TYPE_DICT[opcode_name]
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         WLAN_INTF_OPCODE,
                         c_void_p,
                         POINTER(DWORD),
                         POINTER(POINTER(return_type)),
                         POINTER(WLAN_OPCODE_VALUE_TYPE)]
    func_ref.restype = DWORD
    pdwDataSize = DWORD()
    ppData = pointer(return_type())
    pWlanOpcodeValueType = WLAN_OPCODE_VALUE_TYPE()
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      OpCode,
                      None,
                      byref(pdwDataSize),
                      byref(ppData),
                      byref(pWlanOpcodeValueType))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanQueryInterface failed", result)
    return ppData


def WlanSetProfile(hClientHandle: HANDLE, pInterfaceGuid: GUID, dwFlags: int, strProfileXml: str, strAllUserProfileSecurity: Optional[str] = None, bOverwrite: bool = True) -> int:
    """
        DWORD WINAPI WlanSetProfile(
          _In_      HANDLE  hClientHandle,
          _In_      const GUID    *pInterfaceGuid,
          _In_      DWORD   dwFlags,
          _In_      LPCWSTR strProfileXml,
          _In_opt_  LPCWSTR strAllUserProfileSecurity,
          _In_      BOOL    bOverwrite,
          _Reserved_ PVOID   pReserved,
          _Out_     DWORD   *pdwReasonCode
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetProfile
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         DWORD,
                         LPCWSTR,
                         LPCWSTR,
                         BOOL,
                         c_void_p,
                         POINTER(DWORD)]
    func_ref.restype = DWORD
    reason_code = DWORD()
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      dwFlags,
                      strProfileXml,
                      strAllUserProfileSecurity,
                      bOverwrite,
                      None,
                      byref(reason_code))
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanSetProfile failed (Reason Code: {reason_code.value})", result)
    return result


def WlanReasonCodeToString(dwReasonCode: int) -> str:
    """
        DWORD WINAPI WlanReasonCodeToString(
          _In_       DWORD  dwReasonCode,
          _In_       DWORD  dwBufferSize,
          _In_       PWCHAR pStringBuffer,
          _Reserved_ PVOID  pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanReasonCodeToString
    func_ref.argtypes = [DWORD, DWORD, LPWSTR, c_void_p]
    func_ref.restype = DWORD
    buffer_size = 1024
    string_buffer = create_unicode_buffer(buffer_size)
    result = func_ref(dwReasonCode, buffer_size, string_buffer, None)
    if result != ERROR_SUCCESS:
        return f"Unknown Reason Code {dwReasonCode}"
    return string_buffer.value


class WLAN_INTERFACE_CAPABILITY(Structure):
    """
        typedef struct _WLAN_INTERFACE_CAPABILITY {
          WLAN_INTERFACE_TYPE interfaceType;
          BOOL                 bDot11ConnectionSupported;
          DWORD                dwMaxDesiredBssidListSize;
          DWORD                dwMaxDesiredSsidListSize;
          DWORD                dwNumberOfSupportedPhys;
          DOT11_PHY_TYPE       dot11PhyTypes[WLAN_MAX_PHY_TYPE_NUMBER];
        } WLAN_INTERFACE_CAPABILITY, *PWLAN_INTERFACE_CAPABILITY;
    """
    _fields_ = [("interfaceType", c_uint),
                ("bDot11ConnectionSupported", BOOL),
                ("dwMaxDesiredBssidListSize", DWORD),
                ("dwMaxDesiredSsidListSize", DWORD),
                ("dwNumberOfSupportedPhys", DWORD),
                ("dot11PhyTypes", DOT11_PHY_TYPE * WLAN_MAX_PHY_TYPE_NUMBER)]

def WlanGetInterfaceCapability(hClientHandle: HANDLE, pInterfaceGuid: GUID) -> POINTER(WLAN_INTERFACE_CAPABILITY):
    """
        DWORD WINAPI WlanGetInterfaceCapability(
          _In_       HANDLE                     hClientHandle,
          _In_       const GUID                 *pInterfaceGuid,
          _Reserved_ PVOID                      pReserved,
          _Out_      PWLAN_INTERFACE_CAPABILITY *ppCapability
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetInterfaceCapability
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         c_void_p,
                         POINTER(POINTER(WLAN_INTERFACE_CAPABILITY))]
    func_ref.restype = DWORD
    ppCapability = pointer(WLAN_INTERFACE_CAPABILITY())
    result = func_ref(hClientHandle, byref(pInterfaceGuid), None, byref(ppCapability))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetInterfaceCapability failed", result)
    return ppCapability


def WlanAllocateMemory(dwMemorySize: int) -> c_void_p:
    """
        PVOID WINAPI WlanAllocateMemory(
          _In_ DWORD dwMemorySize
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanAllocateMemory
    func_ref.argtypes = [DWORD]
    func_ref.restype = c_void_p
    result = func_ref(dwMemorySize)
    if not result:
        raise Win32WifiError("WlanAllocateMemory failed", 8) # ERROR_NOT_ENOUGH_MEMORY
    return result


class DOT11_NETWORK(Structure):
    """
        typedef struct _DOT11_NETWORK {
          DOT11_SSID     dot11Ssid;
          DOT11_BSS_TYPE dot11BssType;
        } DOT11_NETWORK, *PDOT11_NETWORK;
    """
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("dot11BssType", DOT11_BSS_TYPE)]


class WLAN_FILTER_LIST(Structure):
    """
        typedef struct _WLAN_FILTER_LIST {
          DWORD         dwNumberOfItems;
          DWORD         dwIndex;
          DOT11_NETWORK Network[1];
        } WLAN_FILTER_LIST, *PWLAN_FILTER_LIST;
    """
    _fields_ = [("dwNumberOfItems", DWORD),
                ("dwIndex", DWORD),
                ("Network", DOT11_NETWORK * 1)]


WLAN_FILTER_LIST_TYPE = c_int
WLAN_FILTER_LIST_TYPE_DICT = {
    0: "wlan_filter_list_type_gp_permit",
    1: "wlan_filter_list_type_gp_deny",
    2: "wlan_filter_list_type_user_permit",
    3: "wlan_filter_list_type_user_deny"
}

WLAN_UI_COMPLETION_SOURCE = c_int
WLAN_UI_COMPLETION_SOURCE_DICT = {
    0: "wlan_ui_completion_source_unknown",
    1: "wlan_ui_completion_source_user",
    2: "wlan_ui_completion_source_system"
}

def WlanGetFilterList(hClientHandle: HANDLE, wlanFilterListType: int) -> POINTER(WLAN_FILTER_LIST):
    """
        DWORD WINAPI WlanGetFilterList(
          _In_       HANDLE             hClientHandle,
          _In_       WLAN_FILTER_LIST_TYPE wlanFilterListType,
          _Reserved_ PVOID              pReserved,
          _Out_      PWLAN_FILTER_LIST  *ppWlanFilterList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetFilterList
    func_ref.argtypes = [HANDLE, c_int, c_void_p, POINTER(POINTER(WLAN_FILTER_LIST))]
    func_ref.restype = DWORD
    ppFilterList = pointer(WLAN_FILTER_LIST())
    result = func_ref(hClientHandle, wlanFilterListType, None, byref(ppFilterList))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetFilterList failed", result)
    return ppFilterList


def WlanSetFilterList(hClientHandle: HANDLE, wlanFilterListType: int, pWlanFilterList: Optional[WLAN_FILTER_LIST]) -> int:
    """
        DWORD WINAPI WlanSetFilterList(
          _In_       HANDLE             hClientHandle,
          _In_       WLAN_FILTER_LIST_TYPE wlanFilterListType,
          _In_opt_   const PWLAN_FILTER_LIST pWlanFilterList,
          _Reserved_ PVOID              pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetFilterList
    func_ref.argtypes = [HANDLE, c_int, POINTER(WLAN_FILTER_LIST), c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, wlanFilterListType, pWlanFilterList, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanSetFilterList failed", result)
    return result


WLAN_AUTOCONF_OPCODE = c_uint
WLAN_AUTOCONF_OPCODE_DICT = {
    0: "wlan_autoconf_opcode_start",
    1: "wlan_autoconf_opcode_show_denied_networks",
    2: "wlan_autoconf_opcode_power_setting",
    3: "wlan_autoconf_opcode_only_use_group_profiles_for_allowed_networks",
    4: "wlan_autoconf_opcode_allow_explicit_creds",
    5: "wlan_autoconf_opcode_block_period",
    6: "wlan_autoconf_opcode_allow_virtual_station_extensibility",
    7: "wlan_autoconf_opcode_end"
}


def WlanQueryAutoConfigParameter(hClientHandle: HANDLE, OpCode: WLAN_AUTOCONF_OPCODE) -> Tuple[POINTER(Any), int]:
    """
        DWORD WINAPI WlanQueryAutoConfigParameter(
          _In_       HANDLE           hClientHandle,
          _In_       WLAN_AUTOCONF_OPCODE OpCode,
          _Reserved_ PVOID            pReserved,
          _Out_      PDWORD           pdwDataSize,
          _Out_      PVOID            *ppData,
          _Out_opt_  PWLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanQueryAutoConfigParameter
    func_ref.argtypes = [HANDLE, WLAN_AUTOCONF_OPCODE, c_void_p, POINTER(DWORD), POINTER(c_void_p), POINTER(WLAN_OPCODE_VALUE_TYPE)]
    func_ref.restype = DWORD
    dwDataSize = DWORD()
    ppData = c_void_p()
    pWlanOpcodeValueType = WLAN_OPCODE_VALUE_TYPE()
    result = func_ref(hClientHandle, OpCode, None, byref(dwDataSize), byref(ppData), byref(pWlanOpcodeValueType))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanQueryAutoConfigParameter failed", result)
    return ppData, dwDataSize.value


def WlanSetAutoConfigParameter(hClientHandle: HANDLE, OpCode: WLAN_AUTOCONF_OPCODE, dwDataSize: int, pData: c_void_p) -> int:
    """
        DWORD WINAPI WlanSetAutoConfigParameter(
          _In_       HANDLE           hClientHandle,
          _In_       WLAN_AUTOCONF_OPCODE OpCode,
          _In_       DWORD            dwDataSize,
          _In_       const PVOID      pData,
          _Reserved_ PVOID            pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetAutoConfigParameter
    func_ref.argtypes = [HANDLE, WLAN_AUTOCONF_OPCODE, DWORD, c_void_p, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, OpCode, dwDataSize, pData, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanSetAutoConfigParameter failed", result)
    return result


def WlanSaveTemporaryProfile(hClientHandle: HANDLE, pInterfaceGuid: GUID, strProfileName: str, strAllUserProfileSecurity: Optional[str], dwFlags: int, bOverwrite: bool) -> int:
    """
        DWORD WINAPI WlanSaveTemporaryProfile(
          _In_       HANDLE     hClientHandle,
          _In_       const GUID *pInterfaceGuid,
          _In_       LPCWSTR    strProfileName,
          _In_opt_   LPCWSTR    strAllUserProfileSecurity,
          _In_       DWORD      dwFlags,
          _In_       BOOL       bOverwrite,
          _Reserved_ PVOID      pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSaveTemporaryProfile
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, LPCWSTR, DWORD, BOOL, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strProfileName, strAllUserProfileSecurity, dwFlags, bOverwrite, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanSaveTemporaryProfile failed for {strProfileName}", result)
    return result


def WlanUIEditProfile(dwClientVersion: int, strProfileName: str, pInterfaceGuid: GUID, hWnd: int, wlCompletionSource: int) -> int:
    """
        DWORD WINAPI WlanUIEditProfile(
          _In_ DWORD dwClientVersion,
          _In_ LPCWSTR strProfileName,
          _In_ GUID *pInterfaceGuid,
          _In_ HWND hWnd,
          _In_ WLAN_UI_COMPLETION_SOURCE wlCompletionSource,
          _In_ PVOID pReserved,
          _Out_ PWLAN_REASON_CODE pWlanReasonCode
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanUIEditProfile
    func_ref.argtypes = [DWORD, LPCWSTR, POINTER(GUID), HANDLE, c_int, c_void_p, POINTER(WLAN_REASON_CODE)]
    func_ref.restype = DWORD
    reason_code = WLAN_REASON_CODE()
    # hWnd is a window handle, wlCompletionSource is an enum
    result = func_ref(dwClientVersion, strProfileName, byref(pInterfaceGuid), hWnd, wlCompletionSource, None, byref(reason_code))
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanUIEditProfile failed (Reason: {reason_code.value})", result)
    return result


class EAP_TYPE(Structure):
    """
        typedef struct _EAP_TYPE {
          BYTE  type;
          DWORD dwVendorId;
          DWORD dwVendorType;
        } EAP_TYPE;
    """
    _fields_ = [("type", c_ubyte),
                ("dwVendorId", DWORD),
                ("dwVendorType", DWORD)]


class EAP_METHOD_TYPE(Structure):
    """
        typedef struct _EAP_METHOD_TYPE {
          EAP_TYPE eapType;
          DWORD    dwAuthorId;
        } EAP_METHOD_TYPE;
    """
    _fields_ = [("eapType", EAP_TYPE),
                ("dwAuthorId", DWORD)]


def WlanSetProfileEapUserData(hClientHandle: HANDLE, pInterfaceGuid: GUID, strProfileName: str, eapMethodType: EAP_METHOD_TYPE, dwFlags: int, dwEapUserDataSize: int, pbEapUserData: c_void_p) -> int:
    """
        DWORD WINAPI WlanSetProfileEapUserData(
          _In_ HANDLE          hClientHandle,
          _In_ const GUID      *pInterfaceGuid,
          _In_ LPCWSTR         strProfileName,
          _In_ EAP_METHOD_TYPE eapMethodType,
          _In_ DWORD           dwFlags,
          _In_ DWORD           dwEapUserDataSize,
          _In_ const LPBYTE    pbEapUserData,
               PVOID           pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetProfileEapUserData
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, EAP_METHOD_TYPE, DWORD, DWORD, c_void_p, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strProfileName, eapMethodType, dwFlags, dwEapUserDataSize, pbEapUserData, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanSetProfileEapUserData failed for {strProfileName}", result)
    return result


def WlanSetProfileEapXmlUserData(hClientHandle: HANDLE, pInterfaceGuid: GUID, strProfileName: str, dwFlags: int, strEapXmlUserData: str) -> int:
    """
        DWORD WINAPI WlanSetProfileEapXmlUserData(
          _In_ HANDLE     hClientHandle,
          _In_ const GUID *pInterfaceGuid,
          _In_ LPCWSTR    strProfileName,
          _In_ DWORD      dwFlags,
          _In_ LPCWSTR    strEapXmlUserData,
               PVOID      pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetProfileEapXmlUserData
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, DWORD, LPCWSTR, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strProfileName, dwFlags, strEapXmlUserData, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanSetProfileEapXmlUserData failed for {strProfileName}", result)
    return result


WLAN_SECURABLE_OBJECT = c_int
WLAN_SECURABLE_OBJECT_DICT = {
    0: "wlan_securable_object_permit_list",
    1: "wlan_securable_object_deny_list",
    2: "wlan_securable_object_acm_settings",
    3: "wlan_securable_object_profile_list",
    4: "wlan_securable_object_profile",
    5: "wlan_securable_object_ihv_settings",
    6: "wlan_securable_object_active_setting"
}


def WlanGetSecuritySettings(hClientHandle: HANDLE, SecurableObject: WLAN_SECURABLE_OBJECT) -> Tuple[WLAN_OPCODE_VALUE_TYPE, str, int]:
    """
        DWORD WINAPI WlanGetSecuritySettings(
          _In_            HANDLE                hClientHandle,
          _In_            WLAN_SECURABLE_OBJECT SecurableObject,
          _Out_opt_       PWLAN_OPCODE_VALUE_TYPE pValueType,
          _Out_           LPWSTR                *pstrCurrentSDDL,
          _Out_           PDWORD                pdwGrantedAccess
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetSecuritySettings
    func_ref.argtypes = [HANDLE, WLAN_SECURABLE_OBJECT, POINTER(WLAN_OPCODE_VALUE_TYPE), POINTER(LPWSTR), POINTER(DWORD)]
    func_ref.restype = DWORD
    value_type = WLAN_OPCODE_VALUE_TYPE()
    sddl = LPWSTR()
    granted_access = DWORD()
    result = func_ref(hClientHandle, SecurableObject, byref(value_type), byref(sddl), byref(granted_access))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetSecuritySettings failed", result)
    return value_type, sddl.value, granted_access.value


def WlanSetSecuritySettings(hClientHandle: HANDLE, SecurableObject: WLAN_SECURABLE_OBJECT, strModifiedSDDL: str) -> int:
    """
        DWORD WINAPI WlanSetSecuritySettings(
          _In_ HANDLE                hClientHandle,
          _In_ WLAN_SECURABLE_OBJECT SecurableObject,
          _In_ LPCWSTR               strModifiedSDDL
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetSecuritySettings
    func_ref.argtypes = [HANDLE, WLAN_SECURABLE_OBJECT, LPCWSTR]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, SecurableObject, strModifiedSDDL)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanSetSecuritySettings failed", result)
    return result


def WlanGetProfileCustomUserData(hClientHandle: HANDLE, pInterfaceGuid: GUID, strProfileName: str) -> Tuple[int, c_void_p]:
    """
        DWORD WINAPI WlanGetProfileCustomUserData(
          _In_       HANDLE     hClientHandle,
          _In_       const GUID *pInterfaceGuid,
          _In_       LPCWSTR    strProfileName,
          _Reserved_ PVOID      pReserved,
          _Out_      PDWORD     pdwDataSize,
          _Out_      PBYTE      *ppData
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetProfileCustomUserData
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, c_void_p, POINTER(DWORD), POINTER(c_void_p)]
    func_ref.restype = DWORD
    dwDataSize = DWORD()
    ppData = c_void_p()
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strProfileName, None, byref(dwDataSize), byref(ppData))
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanGetProfileCustomUserData failed for {strProfileName}", result)
    return dwDataSize.value, ppData


def WlanSetProfileCustomUserData(hClientHandle: HANDLE, pInterfaceGuid: GUID, strProfileName: str, dwDataSize: int, pData: c_void_p) -> int:
    """
        DWORD WINAPI WlanSetProfileCustomUserData(
          _In_       HANDLE     hClientHandle,
          _In_       const GUID *pInterfaceGuid,
          _In_       LPCWSTR    strProfileName,
          _In_       DWORD      dwDataSize,
          _In_       const PBYTE pData,
          _Reserved_ PVOID      pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetProfileCustomUserData
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, DWORD, c_void_p, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strProfileName, dwDataSize, pData, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanSetProfileCustomUserData failed for {strProfileName}", result)
    return result


WLAN_HOSTED_NETWORK_STATE = c_int
WLAN_HOSTED_NETWORK_STATE_DICT = {
    0: "wlan_hosted_network_unavailable",
    1: "wlan_hosted_network_idle",
    2: "wlan_hosted_network_active"
}


WLAN_HOSTED_NETWORK_OPCODE = c_int
WLAN_HOSTED_NETWORK_OPCODE_DICT = {
    0: "wlan_hosted_network_opcode_connection_settings",
    1: "wlan_hosted_network_opcode_security_settings",
    2: "wlan_hosted_network_opcode_station_profile",
    3: "wlan_hosted_network_opcode_enable"
}


WLAN_HOSTED_NETWORK_REASON = c_int
WLAN_HOSTED_NETWORK_REASON_DICT = {
    0: "wlan_hosted_network_reason_success",
    1: "wlan_hosted_network_reason_failure",
    2: "wlan_hosted_network_reason_bad_parameters",
    3: "wlan_hosted_network_reason_service_shutting_down",
    4: "wlan_hosted_network_reason_insufficient_resources",
    5: "wlan_hosted_network_reason_elevation_required",
    6: "wlan_hosted_network_reason_read_only",
    7: "wlan_hosted_network_reason_persistence_failed",
    8: "wlan_hosted_network_reason_crypt_error",
    9: "wlan_hosted_network_reason_impersonation_failed",
    10: "wlan_hosted_network_reason_stop_before_start",
    11: "wlan_hosted_network_reason_interface_available",
    12: "wlan_hosted_network_reason_interface_unavailable",
    13: "wlan_hosted_network_reason_miniport_stopped",
    14: "wlan_hosted_network_reason_miniport_started",
    15: "wlan_hosted_network_reason_incompatible_connection_started",
    16: "wlan_hosted_network_reason_incompatible_connection_stopped",
    17: "wlan_hosted_network_reason_user_if_not_allowed",
    18: "wlan_hosted_network_reason_not_allowed",
    19: "wlan_hosted_network_reason_kernel_mode_driver_no_ui",
    20: "wlan_hosted_network_reason_miniport_internal_error",
    21: "wlan_hosted_network_reason_if_operator_not_allowed",
    22: "wlan_hosted_network_reason_already_started",
}


class WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS(Structure):
    """
        typedef struct _WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS {
          DOT11_SSID hostedNetworkSSID;
          DWORD      dwMaxNumberOfPeers;
        } WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS, *PWLAN_HOSTED_NETWORK_CONNECTION_SETTINGS;
    """
    _fields_ = [("hostedNetworkSSID", DOT11_SSID),
                ("dwMaxNumberOfPeers", DWORD)]


class WLAN_HOSTED_NETWORK_SECURITY_SETTINGS(Structure):
    """
        typedef struct _WLAN_HOSTED_NETWORK_SECURITY_SETTINGS {
          DOT11_AUTH_ALGORITHM   dot11AuthAlgorithm;
          DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
        } WLAN_HOSTED_NETWORK_SECURITY_SETTINGS, *PWLAN_HOSTED_NETWORK_SECURITY_SETTINGS;
    """
    _fields_ = [("dot11AuthAlgorithm", DOT11_AUTH_ALGORITHM_TYPE),
                ("dot11CipherAlgorithm", DOT11_CIPHER_ALGORITHM_TYPE)]


class WLAN_HOSTED_NETWORK_PEER_STATE(Structure):
    """
        typedef struct _WLAN_HOSTED_NETWORK_PEER_STATE {
          DOT11_MAC_ADDRESS PeerMacAddress;
          WLAN_HOSTED_NETWORK_PEER_AUTH_STATE PeerAuthState;
        } WLAN_HOSTED_NETWORK_PEER_STATE, *PWLAN_HOSTED_NETWORK_PEER_STATE;
    """
    _fields_ = [("PeerMacAddress", DOT11_MAC_ADDRESS),
                ("PeerAuthState", c_int)]


class WLAN_HOSTED_NETWORK_STATUS(Structure):
    """
        typedef struct _WLAN_HOSTED_NETWORK_STATUS {
          WLAN_HOSTED_NETWORK_STATE      HostedNetworkState;
          GUID                           IPDeviceID;
          DOT11_MAC_ADDRESS              wlanHostedNetworkBSSID;
          DOT11_PHY_TYPE                 dot11PhyType;
          ULONG                          ulChannelFrequency;
          DWORD                          dwNumberOfPeers;
          WLAN_HOSTED_NETWORK_PEER_STATE PeerList[1];
        } WLAN_HOSTED_NETWORK_STATUS, *PWLAN_HOSTED_NETWORK_STATUS;
    """
    _fields_ = [("HostedNetworkState", WLAN_HOSTED_NETWORK_STATE),
                ("IPDeviceID", GUID),
                ("wlanHostedNetworkBSSID", DOT11_MAC_ADDRESS),
                ("dot11PhyType", DOT11_PHY_TYPE),
                ("ulChannelFrequency", c_ulong),
                ("dwNumberOfPeers", DWORD),
                ("PeerList", WLAN_HOSTED_NETWORK_PEER_STATE * 1)]


def WlanHostedNetworkForceStart(hClientHandle: HANDLE) -> int:
    """
        DWORD WINAPI WlanHostedNetworkForceStart(
          _In_       HANDLE                      hClientHandle,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkForceStart
    func_ref.argtypes = [HANDLE, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkForceStart failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkForceStop(hClientHandle: HANDLE) -> int:
    """
        DWORD WINAPI WlanHostedNetworkForceStop(
          _In_       HANDLE                      hClientHandle,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkForceStop
    func_ref.argtypes = [HANDLE, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkForceStop failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkInitSettings(hClientHandle: HANDLE) -> int:
    """
        DWORD WINAPI WlanHostedNetworkInitSettings(
          _In_       HANDLE                      hClientHandle,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkInitSettings
    func_ref.argtypes = [HANDLE, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkInitSettings failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkQueryProperty(hClientHandle: HANDLE, OpCode: WLAN_HOSTED_NETWORK_OPCODE) -> Tuple[int, c_void_p, WLAN_OPCODE_VALUE_TYPE]:
    """
        DWORD WINAPI WlanHostedNetworkQueryProperty(
          _In_       HANDLE                     hClientHandle,
          _In_       WLAN_HOSTED_NETWORK_OPCODE OpCode,
          _Out_      PDWORD                     pdwDataSize,
          _Out_      PVOID                      *ppvData,
          _Out_      PWLAN_OPCODE_VALUE_TYPE    pwlanOpcodeValueType,
          _Reserved_ PVOID                      pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkQueryProperty
    func_ref.argtypes = [HANDLE, WLAN_HOSTED_NETWORK_OPCODE, POINTER(DWORD), POINTER(c_void_p), POINTER(WLAN_OPCODE_VALUE_TYPE), c_void_p]
    func_ref.restype = DWORD
    dwDataSize = DWORD()
    ppvData = c_void_p()
    pwlanOpcodeValueType = WLAN_OPCODE_VALUE_TYPE()
    result = func_ref(hClientHandle, OpCode, byref(dwDataSize), byref(ppvData), byref(pwlanOpcodeValueType), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanHostedNetworkQueryProperty failed", result)
    return dwDataSize.value, ppvData, pwlanOpcodeValueType


def WlanHostedNetworkQuerySecondaryKey(hClientHandle: HANDLE) -> Tuple[int, c_char_p, bool, bool]:
    """
        DWORD WINAPI WlanHostedNetworkQuerySecondaryKey(
          _In_       HANDLE                      hClientHandle,
          _Out_      PDWORD                      pdwKeyLength,
          _Out_      PUCHAR                      *ppucKeyData,
          _Out_      PBOOL                       pbIsPassphrase,
          _Out_      PBOOL                       pbIsPersistent,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkQuerySecondaryKey
    func_ref.argtypes = [HANDLE, POINTER(DWORD), POINTER(c_char_p), POINTER(BOOL), POINTER(BOOL), POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    dwKeyLength = DWORD()
    ppucKeyData = c_char_p()
    pbIsPassphrase = BOOL()
    pbIsPersistent = BOOL()
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(dwKeyLength), byref(ppucKeyData), byref(pbIsPassphrase), byref(pbIsPersistent), byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkQuerySecondaryKey failed (Reason: {fail_reason.value})", result)
    return dwKeyLength.value, ppucKeyData, bool(pbIsPassphrase.value), bool(pbIsPersistent.value)


def WlanHostedNetworkQueryStatus(hClientHandle: HANDLE) -> POINTER(WLAN_HOSTED_NETWORK_STATUS):
    """
        DWORD WINAPI WlanHostedNetworkQueryStatus(
          _In_       HANDLE                      hClientHandle,
          _Out_      PWLAN_HOSTED_NETWORK_STATUS *ppWlanHostedNetworkStatus,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkQueryStatus
    func_ref.argtypes = [HANDLE, POINTER(POINTER(WLAN_HOSTED_NETWORK_STATUS)), c_void_p]
    func_ref.restype = DWORD
    ppStatus = pointer(WLAN_HOSTED_NETWORK_STATUS())
    result = func_ref(hClientHandle, byref(ppStatus), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanHostedNetworkQueryStatus failed", result)
    return ppStatus


def WlanHostedNetworkRefreshSecuritySettings(hClientHandle: HANDLE) -> int:
    """
        DWORD WINAPI WlanHostedNetworkRefreshSecuritySettings(
          _In_       HANDLE                      hClientHandle,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkRefreshSecuritySettings
    func_ref.argtypes = [HANDLE, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkRefreshSecuritySettings failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkSetProperty(hClientHandle: HANDLE, OpCode: WLAN_HOSTED_NETWORK_OPCODE, dwDataSize: int, pvData: c_void_p) -> int:
    """
        DWORD WINAPI WlanHostedNetworkSetProperty(
          _In_       HANDLE                     hClientHandle,
          _In_       WLAN_HOSTED_NETWORK_OPCODE OpCode,
          _In_       DWORD                      dwDataSize,
          _In_       PVOID                      pvData,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                      pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkSetProperty
    func_ref.argtypes = [HANDLE, WLAN_HOSTED_NETWORK_OPCODE, DWORD, c_void_p, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, OpCode, dwDataSize, pvData, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkSetProperty failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkSetSecondaryKey(hClientHandle: HANDLE, dwKeyLength: int, pucKeyData: bytes, bIsPassphrase: bool, bIsPersistent: bool) -> int:
    """
        DWORD WINAPI WlanHostedNetworkSetSecondaryKey(
          _In_       HANDLE                      hClientHandle,
          _In_       DWORD                       dwKeyLength,
          _In_       PUCHAR                      pucKeyData,
          _In_       BOOL                        bIsPassphrase,
          _In_       BOOL                        bIsPersistent,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkSetSecondaryKey
    func_ref.argtypes = [HANDLE, DWORD, c_char_p, BOOL, BOOL, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, dwKeyLength, pucKeyData, bIsPassphrase, bIsPersistent, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkSetSecondaryKey failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkStartUsing(hClientHandle: HANDLE) -> int:
    """
        DWORD WINAPI WlanHostedNetworkStartUsing(
          _In_       HANDLE                      hClientHandle,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkStartUsing
    func_ref.argtypes = [HANDLE, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkStartUsing failed (Reason: {fail_reason.value})", result)
    return result


def WlanHostedNetworkStopUsing(hClientHandle: HANDLE) -> int:
    """
        DWORD WINAPI WlanHostedNetworkStopUsing(
          _In_       HANDLE                      hClientHandle,
          _Out_opt_  PWLAN_HOSTED_NETWORK_REASON pFailReason,
          _Reserved_ PVOID                       pvReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanHostedNetworkStopUsing
    func_ref.argtypes = [HANDLE, POINTER(WLAN_HOSTED_NETWORK_REASON), c_void_p]
    func_ref.restype = DWORD
    fail_reason = WLAN_HOSTED_NETWORK_REASON()
    result = func_ref(hClientHandle, byref(fail_reason), None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanHostedNetworkStopUsing failed (Reason: {fail_reason.value})", result)
    return result


class WLAN_RAW_DATA_LIST(Structure):
    """
        typedef struct _WLAN_RAW_DATA_LIST {
          DWORD         dwTotalSize;
          DWORD         dwNumberOfItems;
          WLAN_RAW_DATA RawData[1];
        } WLAN_RAW_DATA_LIST, *PWLAN_RAW_DATA_LIST;
    """
    _fields_ = [("dwTotalSize", DWORD),
                ("dwNumberOfItems", DWORD),
                ("RawData", WLAN_RAW_DATA * 1)]


def WlanExtractPsdIEDataList(hClientHandle: HANDLE, dwIeDataSize: int, pRawIeData: c_void_p, strFormat: str) -> POINTER(WLAN_RAW_DATA_LIST):
    """
        DWORD WINAPI WlanExtractPsdIEDataList(
          _In_            HANDLE           hClientHandle,
          _In_            DWORD            dwIeDataSize,
          _In_            const PBYTE      pRawIeData,
          _In_            LPCWSTR          strFormat,
          _Reserved_      PVOID            pReserved,
          _Out_           PWLAN_RAW_DATA_LIST *ppPsdIEDataList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanExtractPsdIEDataList
    func_ref.argtypes = [HANDLE, DWORD, c_void_p, LPCWSTR, c_void_p, POINTER(POINTER(WLAN_RAW_DATA_LIST))]
    func_ref.restype = DWORD
    ppList = pointer(WLAN_RAW_DATA_LIST())
    result = func_ref(hClientHandle, dwIeDataSize, pRawIeData, strFormat, None, byref(ppList))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanExtractPsdIEDataList failed", result)
    return ppList


def WlanSetPsdIeDataList(hClientHandle: HANDLE, strFormat: Optional[str], pPsdIEDataList: Optional[WLAN_RAW_DATA_LIST]) -> int:
    """
        DWORD WINAPI WlanSetPsdIeDataList(
          _In_            HANDLE           hClientHandle,
          _In_opt_        LPCWSTR          strFormat,
          _In_opt_        const PWLAN_RAW_DATA_LIST pPsdIEDataList,
          _Reserved_      PVOID            pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetPsdIeDataList
    func_ref.argtypes = [HANDLE, LPCWSTR, POINTER(WLAN_RAW_DATA_LIST), c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, strFormat, pPsdIEDataList, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanSetPsdIeDataList failed", result)
    return result


WLAN_IHV_CONTROL_TYPE = c_int
WLAN_IHV_CONTROL_TYPE_DICT = {
    0: "wlan_ihv_control_type_service",
    1: "wlan_ihv_control_type_driver"
}


def WlanIhvControl(hClientHandle: HANDLE, pInterfaceGuid: GUID, Type: WLAN_IHV_CONTROL_TYPE, dwInBufferSize: int, pvInBuffer: c_void_p, dwOutBufferSize: int) -> Tuple[int, c_void_p, int]:
    """
        DWORD WINAPI WlanIhvControl(
          _In_            HANDLE                hClientHandle,
          _In_            const GUID            *pInterfaceGuid,
          _In_            WLAN_IHV_CONTROL_TYPE Type,
          _In_            DWORD                 dwInBufferSize,
          _In_            PVOID                 pvInBuffer,
          _In_            DWORD                 dwOutBufferSize,
          _Out_opt_       PVOID                 pvOutBuffer,
          _Out_           PDWORD                pdwBytesReturned
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanIhvControl
    func_ref.argtypes = [HANDLE, POINTER(GUID), WLAN_IHV_CONTROL_TYPE, DWORD, c_void_p, DWORD, c_void_p, POINTER(DWORD)]
    func_ref.restype = DWORD
    pvOutBuffer = create_string_buffer(dwOutBufferSize) if dwOutBufferSize > 0 else None
    dwBytesReturned = DWORD()
    result = func_ref(hClientHandle, byref(pInterfaceGuid), Type, dwInBufferSize, pvInBuffer, dwOutBufferSize, pvOutBuffer, byref(dwBytesReturned))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanIhvControl failed", result)
    return result, pvOutBuffer, dwBytesReturned.value


def WlanDeviceServiceCommand(hClientHandle: HANDLE, pInterfaceGuid: GUID, pDeviceServiceGuid: GUID, dwOpCode: int, dwInBufferSize: int, pvInBuffer: c_void_p, dwOutBufferSize: int) -> Tuple[int, c_void_p, int]:
    """
        DWORD WINAPI WlanDeviceServiceCommand(
          _In_            HANDLE     hClientHandle,
          _In_            const GUID *pInterfaceGuid,
          _In_            LPCGUID    pDeviceServiceGuid,
          _In_            DWORD      dwOpCode,
          _In_            DWORD      dwInBufferSize,
          _In_            PVOID      pvInBuffer,
          _In_            DWORD      dwOutBufferSize,
          _Out_opt_       PVOID      pvOutBuffer,
          _Out_           PDWORD     pdwBytesReturned
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanDeviceServiceCommand
    func_ref.argtypes = [HANDLE, POINTER(GUID), POINTER(GUID), DWORD, DWORD, c_void_p, DWORD, c_void_p, POINTER(DWORD)]
    func_ref.restype = DWORD
    pvOutBuffer = create_string_buffer(dwOutBufferSize) if dwOutBufferSize > 0 else None
    dwBytesReturned = DWORD()
    result = func_ref(hClientHandle, byref(pInterfaceGuid), byref(pDeviceServiceGuid), dwOpCode, dwInBufferSize, pvInBuffer, dwOutBufferSize, pvOutBuffer, byref(dwBytesReturned))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanDeviceServiceCommand failed", result)
    return result, pvOutBuffer, dwBytesReturned.value


class WLAN_DEVICE_SERVICE_GUID_LIST(Structure):
    """
        typedef struct _WLAN_DEVICE_SERVICE_GUID_LIST {
          DWORD dwNumberOfItems;
          DWORD dwIndex;
          GUID  DeviceServiceGuids[1];
        } WLAN_DEVICE_SERVICE_GUID_LIST, *PWLAN_DEVICE_SERVICE_GUID_LIST;
    """
    _fields_ = [("dwNumberOfItems", DWORD),
                ("dwIndex", DWORD),
                ("DeviceServiceGuids", GUID * 1)]


def WlanGetSupportedDeviceServices(hClientHandle: HANDLE, pInterfaceGuid: GUID) -> POINTER(WLAN_DEVICE_SERVICE_GUID_LIST):
    """
        DWORD WINAPI WlanGetSupportedDeviceServices(
          _In_  HANDLE                      hClientHandle,
          _In_  const GUID                  *pInterfaceGuid,
          _Out) PWLAN_DEVICE_SERVICE_GUID_LIST *ppSupportedDeviceServiceGuidList
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanGetSupportedDeviceServices
    func_ref.argtypes = [HANDLE, POINTER(GUID), POINTER(POINTER(WLAN_DEVICE_SERVICE_GUID_LIST))]
    func_ref.restype = DWORD
    ppList = pointer(WLAN_DEVICE_SERVICE_GUID_LIST())
    result = func_ref(hClientHandle, byref(pInterfaceGuid), byref(ppList))
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanGetSupportedDeviceServices failed", result)
    return ppList


def WlanRegisterVirtualStationNotification(hClientHandle: HANDLE, bRegister: bool) -> int:
    """
        DWORD WINAPI WlanRegisterVirtualStationNotification(
          _In_ HANDLE hClientHandle,
          _In_ BOOL   bRegister,
               PVOID  pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanRegisterVirtualStationNotification
    func_ref.argtypes = [HANDLE, BOOL, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, bRegister, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanRegisterVirtualStationNotification failed", result)
    return result


def WlanRenameProfile(hClientHandle: HANDLE, pInterfaceGuid: GUID, strOldProfileName: str, strNewProfileName: str) -> int:
    """
        DWORD WINAPI WlanRenameProfile(
          _In_       HANDLE     hClientHandle,
          _In_       const GUID *pInterfaceGuid,
          _In_       LPCWSTR    strOldProfileName,
          _In_       LPCWSTR    strNewProfileName,
          _Reserved_ PVOID      pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanRenameProfile
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, LPCWSTR, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strOldProfileName, strNewProfileName, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanRenameProfile failed from {strOldProfileName} to {strNewProfileName}", result)
    return result


def WlanSetProfileList(hClientHandle: HANDLE, pInterfaceGuid: GUID, dwNumberOfItems: int, ppstrProfileNames: POINTER(LPCWSTR)) -> int:
    """
        DWORD WINAPI WlanSetProfileList(
          _In_       HANDLE     hClientHandle,
          _In_       const GUID *pInterfaceGuid,
          _In_       DWORD      dwItems,
          _In_       LPCWSTR    *ppstrProfileNames,
          _Reserved_ PVOID      pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetProfileList
    func_ref.argtypes = [HANDLE, POINTER(GUID), DWORD, POINTER(LPCWSTR), c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), dwNumberOfItems, ppstrProfileNames, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanSetProfileList failed", result)
    return result


def WlanSetProfilePosition(hClientHandle: HANDLE, pInterfaceGuid: GUID, strProfileName: str, dwPosition: int) -> int:
    """
        DWORD WINAPI WlanSetProfilePosition(
          _In_       HANDLE     hClientHandle,
          _In_       const GUID *pInterfaceGuid,
          _In_       LPCWSTR    strProfileName,
          _In_       DWORD      dwPosition,
          _Reserved_ PVOID      pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetProfilePosition
    func_ref.argtypes = [HANDLE, POINTER(GUID), LPCWSTR, DWORD, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), strProfileName, dwPosition, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError(f"WlanSetProfilePosition failed for {strProfileName}", result)
    return result


def WlanSetInterface(hClientHandle: HANDLE, pInterfaceGuid: GUID, OpCode: WLAN_INTF_OPCODE, dwDataSize: int, pData: c_void_p) -> int:
    """
        DWORD WINAPI WlanSetInterface(
          _In_       HANDLE           hClientHandle,
          _In_       const GUID       *pInterfaceGuid,
          _In_       WLAN_INTF_OPCODE OpCode,
          _In_       DWORD            dwDataSize,
          _In_       PVOID            pData,
          _Reserved_ PVOID            pReserved
        );
    """
    _check_wlanapi()
    func_ref = wlanapi.WlanSetInterface
    func_ref.argtypes = [HANDLE, POINTER(GUID), WLAN_INTF_OPCODE, DWORD, c_void_p, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, byref(pInterfaceGuid), OpCode, dwDataSize, pData, None)
    if result != ERROR_SUCCESS:
        raise Win32WifiError("WlanSetInterface failed", result)
    return result

