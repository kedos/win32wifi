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
from datetime import datetime
from enum import Enum
import functools
import time
import xmltodict
from xml.dom import minidom

from comtypes import GUID
from win32wifi.Win32NativeWifiApi import *

NULL = None

class WirelessInterface(object):
    def __init__(self, wlan_iface_info):
        self.description = wlan_iface_info.strInterfaceDescription
        self.guid = GUID(wlan_iface_info.InterfaceGuid)
        self.guid_string = str(wlan_iface_info.InterfaceGuid)
        self.state = wlan_iface_info.isState
        self.state_string = WLAN_INTERFACE_STATE_DICT[self.state]

    def __str__(self):
        result = ""
        result += "Description: %s\n" % self.description
        result += "GUID: %s\n" % self.guid
        result += "State: %s" % self.state_string
        return result


class InformationElement(object):
    def __init__(self, element_id, length, body):
        self.element_id = element_id
        self.length = length
        self.body = body

    def __str__(self):
        result = ""
        result += "Element ID: %d\n" % self.element_id
        result += "Length: %d\n" % self.length
        result += "Body: %r" % self.body
        return result


class WirelessNetwork(object):
    def __init__(self, wireless_network):
        self.ssid = wireless_network.dot11Ssid.SSID[:DOT11_SSID_MAX_LENGTH].decode()
        self.profile_name = wireless_network.ProfileName
        self.bss_type = DOT11_BSS_TYPE_DICT_KV[wireless_network.dot11BssType]
        self.number_of_bssids = wireless_network.NumberOfBssids
        self.connectable = bool(wireless_network.NetworkConnectable)
        self.number_of_phy_types = wireless_network.NumberOfPhyTypes
        self.signal_quality = wireless_network.wlanSignalQuality
        self.security_enabled = bool(wireless_network.SecurityEnabled)
        auth = wireless_network.dot11DefaultAuthAlgorithm
        self.auth = DOT11_AUTH_ALGORITHM_DICT[auth]
        cipher = wireless_network.dot11DefaultCipherAlgorithm
        self.cipher = DOT11_CIPHER_ALGORITHM_DICT[cipher]
        self.flags = wireless_network.Flags

    def __str__(self):
        result = ""
        if not self.profile_name:
            self.profile_name = "<No Profile>"
        result += "Profile Name: %s\n" % self.profile_name
        result += "SSID: %s\n" % self.ssid
        result += "BSS Type: %s\n" % self.bss_type
        result += "Number of BSSIDs: %d\n" % self.number_of_bssids
        result += "Connectable: %r\n" % self.connectable
        result += "Number of PHY types: %d\n" % self.number_of_phy_types
        result += "Signal Quality: %d%%\n" % self.signal_quality
        result += "Security Enabled: %r\n" % self.security_enabled
        result += "Authentication: %s\n" % self.auth
        result += "Cipher: %s\n" % self.cipher
        result += "Flags: %d\n" % self.flags
        return result


class WirelessNetworkBss(object):
    def __init__(self, bss_entry):
        self.ssid = bss_entry.dot11Ssid.SSID[:DOT11_SSID_MAX_LENGTH].decode()
        self.link_quality = bss_entry.LinkQuality
        self.bssid = ":".join(map(lambda x: "%02X" % x, bss_entry.dot11Bssid))
        self.bss_type = DOT11_BSS_TYPE_DICT_KV[bss_entry.dot11BssType]
        self.phy_type = DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType]
        self.rssi = bss_entry.Rssi
        self.ch_center_frequency = bss_entry.ChCenterFrequency
        self.capabilities = bss_entry.CapabilityInformation
        self.__process_information_elements(bss_entry)
        self.__process_information_elements2()

    def __process_information_elements(self, bss_entry):
        self.raw_information_elements = []
        bss_entry_pointer = addressof(bss_entry)
        ie_offset = bss_entry.IeOffset
        data_type = (c_char * bss_entry.IeSize)
        ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
        for byte in ie_buffer:
            self.raw_information_elements.append(byte)

    def __process_information_elements2(self):
        MINIMAL_IE_SIZE = 3
        self.information_elements = []
        aux = self.raw_information_elements
        index = 0
        while(index < len(aux) - MINIMAL_IE_SIZE):
            eid = ord(aux[index])
            index += 1
            length = ord(aux[index])
            index += 1
            body = aux[index:index + length]
            index += length
            ie = InformationElement(eid, length, body)
            self.information_elements.append(ie)

    def __str__(self):
        result = ""
        result += "BSSID: %s\n" % self.bssid
        result += "SSID: %s\n" % self.ssid
        result += "Link Quality: %d%%\n" % self.link_quality
        result += "BSS Type: %s\n" % self.bss_type
        result += "PHY Type: %s\n" % self.phy_type
        result += "Capabilities: %d\n" % self.capabilities
        # result += "Raw Information Elements:\n"
        # result += "%r" % self.raw_information_elements
        result += "\nInformation Elements:\n"
        for ie in self.information_elements:
            lines = str(ie).split("\n")
            for line in lines:
                result += " + %s\n" % line
            result += "\n"
        return result


class WirelessProfile(object):
    def __init__(self, wireless_profile, xml):
        self.name = wireless_profile.ProfileName
        self.flags = wireless_profile.Flags
        self.xml = xml

        self._parse_xml(self.xml)

    def _parse_xml(self, xml):
        d = xmltodict.parse(xml)
        self.ssid = d['WLANProfile']['SSIDConfig']['SSID']['name']

    @staticmethod
    def generate_xml(wireless_network, psk):

        root = minidom.Document()
        profile = root.createElement("WLANProfile")
        profile.setAttribute("xmlns", "http://www.microsoft.com/networking/WLAN/profile/v1")
        root.appendChild(profile)

        name = root.createElement("name")
        name.appendChild(root.createTextNode(wireless_network.ssid))
        profile.appendChild(name)

        ssid_config = root.createElement("SSIDConfig")
        ssid = root.createElement("SSID")
        ssid_hex = root.createElement("hex")
        ssid_hex.appendChild(root.createTextNode(wireless_network.ssid.encode().hex().upper()))
        ssid.appendChild(ssid_hex)
        ssid_name = root.createElement("name")
        ssid_name.appendChild(root.createTextNode(wireless_network.ssid))
        ssid.appendChild(ssid_name)
        ssid_config.appendChild(ssid)
        profile.appendChild(ssid_config)

        connection_type = root.createElement("connectionType")
        connection_type_value = {
            "dot11_BSS_type_infrastructure": "ESS",
            "dot11_BSS_type_independent": "IBSS",
            "dot11_BSS_type_any": "ESS"
        }.get(wireless_network.bss_type)
        connection_type.appendChild(root.createTextNode(connection_type_value))
        profile.appendChild(connection_type)

        connection_mode = root.createElement("connectionMode")
        connection_mode.appendChild(root.createTextNode("manual"))
        profile.appendChild(connection_mode)

        msm = root.createElement("MSM")
        security = root.createElement("security")
        auth_encryption = root.createElement("authEncryption")
        authentication = root.createElement("authentication")
        authentication_value = {
            "DOT11_AUTH_ALGO_80211_OPEN": "open",
            "DOT11_AUTH_ALGO_80211_SHARED_KEY": "shared",
            "DOT11_AUTH_ALGO_WPA": "WPA",
            "DOT11_AUTH_ALGO_WPA_PSK": "WPAPSK",
            "DOT11_AUTH_ALGO_WPA_NONE": "",
            "DOT11_AUTH_ALGO_RSNA": "WPA2",
            "DOT11_AUTH_ALGO_RSNA_PSK": "WPA2PSK",
            "DOT11_AUTH_ALGO_WPA3": "WPA3",
            "DOT11_AUTH_ALGO_WPA3_SAE": "WPA3PSK",
            "DOT11_AUTH_ALGO_IHV_START": "",
            "DOT11_AUTH_ALGO_IHV_END": ""
        }.get(wireless_network.auth)
        authentication.appendChild(root.createTextNode(authentication_value))
        auth_encryption.appendChild(authentication)
        encryption = root.createElement("encryption")
        encryption_value = {
            "DOT11_CIPHER_ALGO_NONE": "none",
            "DOT11_CIPHER_ALGO_WEP40": "WEP",
            "DOT11_CIPHER_ALGO_TKIP": "TKIP",
            "DOT11_CIPHER_ALGO_CCMP": "AES",
            "DOT11_CIPHER_ALGO_WEP104": "WEP",
            "DOT11_CIPHER_ALGO_BIP": "",
            "DOT11_CIPHER_ALGO_WPA_USE_GROUP": "",
            "DOT11_CIPHER_ALGO_RSN_USE_GROUP": "",
            "DOT11_CIPHER_ALGO_WEP": "WEP",
            "DOT11_CIPHER_ALGO_IHV_START": "",
            "DOT11_CIPHER_ALGO_IHV_END": ""
        }.get(wireless_network.cipher)
        encryption.appendChild(root.createTextNode(encryption_value))
        auth_encryption.appendChild(encryption)
        security.appendChild(auth_encryption)
        if psk is not None:
            shared_key = root.createElement("sharedKey")
            key_type = root.createElement("keyType")
            key_type.appendChild(root.createTextNode("passPhrase"))
            shared_key.appendChild(key_type)
            protected = root.createElement("protected")
            protected.appendChild(root.createTextNode("false"))
            shared_key.appendChild(protected)
            key_material = root.createElement("keyMaterial")
            key_material.appendChild(root.createTextNode(psk))
            shared_key.appendChild(key_material)
            security.appendChild(shared_key)
        msm.appendChild(security)
        profile.appendChild(msm)

        return root.toprettyxml(indent="\t")

    def __str__(self):
        result = ""
        result += "Profile Name: %s\n" % self.name
        result += "Flags: %d\n" % self.flags
        result += "XML:\n"
        result += "%s" % self.xml
        return result


class MSMNotificationData(object):
    def __init__(self, msm_notification_data):
        assert isinstance(msm_notification_data, WLAN_MSM_NOTIFICATION_DATA)

        self.connection_mode = WLAN_CONNECTION_MODE_KV[msm_notification_data.wlanConnectionMode]
        self.profile_name = msm_notification_data.strProfileName
        self.ssid = msm_notification_data.dot11Ssid.SSID[:msm_notification_data.dot11Ssid.SSIDLength]
        self.bss_type = DOT11_BSS_TYPE_DICT_KV[msm_notification_data.dot11BssType]
        self.mac_addr = ":".join(["{:02x}".format(x) for x in msm_notification_data.dot11MacAddr[:6]])

    def __str__(self):
        result = ""
        result += "Connection Mode: %s\n" % self.connection_mode
        result += "Profile Name: %s\n" % self.profile_name
        result += "SSID: %s\n" % self.ssid
        result += "BSS Type: %s\n" % self.bss_type
        result += "MAC: %s\n" % self.mac_addr
        return result

class ACMConnectionNotificationData(object):
    def __init__(self, acm_notification_data):
        assert isinstance(acm_notification_data, WLAN_CONNECTION_NOTIFICATION_DATA)

        self.connection_mode = WLAN_CONNECTION_MODE_KV[acm_notification_data.wlanConnectionMode]
        self.profile_name = acm_notification_data.strProfileName
        self.ssid = acm_notification_data.dot11Ssid.SSID[:acm_notification_data.dot11Ssid.SSIDLength]
        self.bss_type = DOT11_BSS_TYPE_DICT_KV[acm_notification_data.dot11BssType]
        self.security_enabled = acm_notification_data.bSecurityEnabled

    def __str__(self):
        result = ""
        result += "Connection Mode: %s\n" % self.connection_mode
        result += "Profile Name: %s\n" % self.profile_name
        result += "SSID: %s\n" % self.ssid
        result += "BSS Type: %s\n" % self.bss_type
        result += "Security Enabled: %r\n" % bool(self.security_enabled)
        return result

def getWirelessInterfaces():
    """Returns a list of WirelessInterface objects based on the wireless
       interfaces available."""
    interfaces_list = []
    handle = WlanOpenHandle()
    wlan_ifaces = WlanEnumInterfaces(handle)
    # Handle the WLAN_INTERFACE_INFO_LIST pointer to get a list of
    # WLAN_INTERFACE_INFO structures.
    data_type = wlan_ifaces.contents.InterfaceInfo._type_
    num = wlan_ifaces.contents.NumberOfItems
    ifaces_pointer = addressof(wlan_ifaces.contents.InterfaceInfo)
    wlan_interface_info_list = (data_type * num).from_address(ifaces_pointer)
    for wlan_interface_info in wlan_interface_info_list:
        wlan_iface = WirelessInterface(wlan_interface_info)
        interfaces_list.append(wlan_iface)
    WlanFreeMemory(wlan_ifaces)
    WlanCloseHandle(handle)
    return interfaces_list


def getWirelessNetworkBssList(wireless_interface):
    """Returns a list of WirelessNetworkBss objects based on the wireless
       networks availables."""
    networks = []
    handle = WlanOpenHandle()
    bss_list = WlanGetNetworkBssList(handle, wireless_interface.guid)
    # Handle the WLAN_BSS_LIST pointer to get a list of WLAN_BSS_ENTRY
    # structures.
    data_type = bss_list.contents.wlanBssEntries._type_
    num = bss_list.contents.NumberOfItems
    bsss_pointer = addressof(bss_list.contents.wlanBssEntries)
    bss_entries_list = (data_type * num).from_address(bsss_pointer)
    for bss_entry in bss_entries_list:
        networks.append(WirelessNetworkBss(bss_entry))
    WlanFreeMemory(bss_list)
    WlanCloseHandle(handle)
    return networks


def getWirelessAvailableNetworkList(wireless_interface):
    """Returns a list of WirelessNetwork objects based on the wireless
       networks availables."""
    networks = []
    handle = WlanOpenHandle()
    network_list = WlanGetAvailableNetworkList(handle, wireless_interface.guid)
    # Handle the WLAN_AVAILABLE_NETWORK_LIST pointer to get a list of
    # WLAN_AVAILABLE_NETWORK structures.
    data_type = network_list.contents.Network._type_
    num = network_list.contents.NumberOfItems
    network_pointer = addressof(network_list.contents.Network)
    networks_list = (data_type * num).from_address(network_pointer)

    for network in networks_list:
        networks.append(WirelessNetwork(network))

    WlanFreeMemory(network_list)
    WlanCloseHandle(handle)
    return networks


def getWirelessProfileXML(wireless_interface, profile_name):
    handle = WlanOpenHandle()
    xml_data = WlanGetProfile(handle,
                              wireless_interface.guid,
                              LPCWSTR(profile_name))
    xml = xml_data.value
    WlanFreeMemory(xml_data)
    WlanCloseHandle(handle)
    return xml


def getWirelessProfiles(wireless_interface):
    """Returns a list of WirelessProfile objects based on the wireless
       profiles."""
    profiles = []
    handle = WlanOpenHandle()
    profile_list = WlanGetProfileList(handle, wireless_interface.guid)
    # Handle the WLAN_PROFILE_INFO_LIST pointer to get a list of
    # WLAN_PROFILE_INFO structures.
    data_type = profile_list.contents.ProfileInfo._type_
    num = profile_list.contents.NumberOfItems
    profile_info_pointer = addressof(profile_list.contents.ProfileInfo)
    profiles_list = (data_type * num).from_address(profile_info_pointer)
    xml_data = None  # safety: there may be no profiles
    for profile in profiles_list:
        xml_data = WlanGetProfile(handle,
                                  wireless_interface.guid,
                                  profile.ProfileName)
        profiles.append(WirelessProfile(profile, xml_data.value))
    WlanFreeMemory(xml_data)
    WlanFreeMemory(profile_list)
    WlanCloseHandle(handle)
    return profiles

def deleteProfile(wireless_interface, profile_name):
    handle = WlanOpenHandle()
    result = WlanDeleteProfile(handle, wireless_interface.guid, profile_name)
    WlanCloseHandle(handle)

    return result

def addProfile(wireless_interface, profile_xml):
    handle = WlanOpenHandle()
    result = WlanSetProfile(handle,
                            wireless_interface.guid,
                            profile_xml)
    WlanCloseHandle(handle)
    return result

def disconnect(wireless_interface):
    """
    """
    handle = WlanOpenHandle()
    try:
        WlanDisconnect(handle, wireless_interface.guid)
    finally:
        WlanCloseHandle(handle)

# TODO(shaked): There is an error 87 when trying to connect to a wifi network.  # @TODO - cfati: Check whether still applies.
def connect(wireless_interface, connection_params):
    """
        The WlanConnect function attempts to connect to a specific network.

        DWORD WINAPI WlanConnect(
          _In_        HANDLE hClientHandle,
          _In_        const GUID *pInterfaceGuid,
          _In_        const PWLAN_CONNECTION_PARAMETERS pConnectionParameters,
          _Reserved_  PVOID pReserved
        );

        connection_params should be a dict with this structure:
        { "connectionMode": "valid connection mode string",
          "profile": ("profile name string" | "profile xml" | None)*,
          "ssid": "ssid string",
          "bssidList": [ "desired bssid string", ... ],
          "bssType": valid bss type int,
          "flags": valid flag dword in 0x00000000 format }
        * Currently, only the name string is supported here.
    """
    handle = WlanOpenHandle()
    cnxp = WLAN_CONNECTION_PARAMETERS()
    connection_mode = connection_params["connectionMode"]
    connection_mode_int = WLAN_CONNECTION_MODE_VK[connection_mode]
    cnxp.wlanConnectionMode = WLAN_CONNECTION_MODE(connection_mode_int)
    # determine strProfile
    if connection_mode in [
                'wlan_connection_mode_profile',  # name
                'wlan_connection_mode_temporary_profile'  # xml
            ]:
        cnxp.strProfile = LPCWSTR(connection_params["profile"])
    else:
        cnxp.strProfile = NULL
    # ssid
    if connection_params["ssid"] is not None:
        dot11Ssid = DOT11_SSID()
        dot11Ssid.SSID = connection_params["ssid"]
        dot11Ssid.SSIDLength = len(connection_params["ssid"])
        cnxp.pDot11Ssid = pointer(dot11Ssid)
    else:
        cnxp.pDot11Ssid = NULL
    # bssidList
    # NOTE: Before this can actually support multiple entries,
    #   the DOT11_BSSID_LIST structure must be rewritten to
    #   dynamically resize itself based on input.
    if connection_params["bssidList"] is not None:
        bssids = []
        for bssidish in connection_params["bssidList"]:
            bssidish = tuple(int(n, 16) for n in bssidish.split(b":"))
            bssids.append((DOT11_MAC_ADDRESS)(*bssidish))
        bssidListEntries = c_ulong(len(bssids))
        bssids = (DOT11_MAC_ADDRESS * len(bssids))(*bssids)
        bssidListHeader = NDIS_OBJECT_HEADER()
        bssidListHeader.Type = NDIS_OBJECT_TYPE_DEFAULT
        bssidListHeader.Revision = DOT11_BSSID_LIST_REVISION_1 # chr()
        bssidListHeader.Size = c_ushort(sizeof(DOT11_BSSID_LIST))
        bssidList = DOT11_BSSID_LIST()
        bssidList.Header = bssidListHeader
        bssidList.uNumOfEntries = bssidListEntries
        bssidList.uTotalNumOfEntries = bssidListEntries
        bssidList.BSSIDs = bssids
        cnxp.pDesiredBssidList = pointer(bssidList)
    else:
        cnxp.pDesiredBssidList = NULL # required for XP
    # look up bssType
    # bssType must match type from profile if a profile is provided
    bssType = DOT11_BSS_TYPE_DICT_VK[connection_params["bssType"]]
    cnxp.dot11BssType = DOT11_BSS_TYPE(bssType)
    # flags
    cnxp.dwFlags = DWORD(connection_params["flags"])
    try:
        result = WlanConnect(handle, wireless_interface.guid, cnxp)
    finally:
        WlanCloseHandle(handle)
    return result

def dot11bssidToString(dot11Bssid):
    return ":".join(map(lambda x: "%02X" % x, dot11Bssid))

def queryInterface(wireless_interface, opcode_item):
    """
    """
    handle = WlanOpenHandle()
    opcode_item_ext = "".join(["wlan_intf_opcode_", opcode_item])
    opcode = None
    for key, val in WLAN_INTF_OPCODE_DICT.items():
        if val == opcode_item_ext:
            opcode = WLAN_INTF_OPCODE(key)
            break
    result = WlanQueryInterface(handle, wireless_interface.guid, opcode)
    WlanCloseHandle(handle)
    r = result.contents
    if opcode_item == "interface_state":
        #WLAN_INTERFACE_STATE
        ext_out = WLAN_INTERFACE_STATE_DICT[r.value]
    elif opcode_item == "current_connection":
        #WLAN_CONNECTION_ATTRIBUTES
        isState = WLAN_INTERFACE_STATE_DICT[r.isState]
        wlanConnectionMode = WLAN_CONNECTION_MODE_KV[r.wlanConnectionMode]
        strProfileName = r.strProfileName
        aa = r.wlanAssociationAttributes
        wlanAssociationAttributes = {
            "dot11Ssid": aa.dot11Ssid.SSID.decode(),
            "dot11BssType": DOT11_BSS_TYPE_DICT_KV[aa.dot11BssType],
            "dot11Bssid": dot11bssidToString(aa.dot11Bssid),
            "dot11PhyType": DOT11_PHY_TYPE_DICT[aa.dot11PhyType],
            "uDot11PhyIndex": c_long(aa.uDot11PhyIndex).value,
            "wlanSignalQuality": c_long(aa.wlanSignalQuality).value,
            "ulRxRate": c_long(aa.ulRxRate).value,
            "ulTxRate": c_long(aa.ulTxRate).value,
        }
        sa = r.wlanSecurityAttributes
        wlanSecurityAttributes = {
            "bSecurityEnabled": sa.bSecurityEnabled,
            "bOneXEnabled": sa.bOneXEnabled,
            "dot11AuthAlgorithm": DOT11_AUTH_ALGORITHM_DICT[sa.dot11AuthAlgorithm],
            "dot11CipherAlgorithm": DOT11_CIPHER_ALGORITHM_DICT[sa.dot11CipherAlgorithm],
        }
        ext_out = {
            "isState": isState,
            "wlanConnectionMode": wlanConnectionMode,
            "strProfileName": strProfileName,
            "wlanAssociationAttributes": wlanAssociationAttributes,
            "wlanSecurityAttributes": wlanSecurityAttributes,
        }
    else:
        ext_out = None
    return result.contents, ext_out


def wndToStr(wlan_notification_data):
    "".join([
        "NotificationSource: %s" % wlan_notification_data.NotificationSource,
        "NotificationCode: %s" % wlan_notification_data.NotificationCode,
        "InterfaceGuid: %s" % wlan_notification_data.InterfaceGuid,
        "dwDataSize: %d" % wlan_notification_data.dwDataSize,
        "pData: %s" % wlan_notification_data.pData,
        ])


class WlanEvent(object):

    ns_type_to_codes_dict = {
        WLAN_NOTIFICATION_SOURCE_NONE:        None,
        WLAN_NOTIFICATION_SOURCE_ONEX:        ONEX_NOTIFICATION_TYPE_ENUM,
        WLAN_NOTIFICATION_SOURCE_ACM:         WLAN_NOTIFICATION_ACM_ENUM,
        WLAN_NOTIFICATION_SOURCE_MSM:         WLAN_NOTIFICATION_MSM_ENUM,
        WLAN_NOTIFICATION_SOURCE_SECURITY:    None,
        WLAN_NOTIFICATION_SOURCE_IHV:         None,
        WLAN_NOTIFICATION_SOURCE_HNWK:        WLAN_HOSTED_NETWORK_NOTIFICATION_CODE_ENUM,
        WLAN_NOTIFICATION_SOURCE_ALL:         ONEX_NOTIFICATION_TYPE_ENUM,
    }

    def __init__(self, original, notificationSource, notificationCode, interfaceGuid, data):
        self.original = original
        self.notificationSource = notificationSource
        self.notificationCode = notificationCode
        self.interfaceGuid = interfaceGuid
        self.data = data

    @staticmethod
    def from_wlan_notification_data(wnd):
        actual = wnd.contents
        """
        typedef struct _WLAN_NOTIFICATION_DATA {
            DWORD NotificationSource;
            DWORD NotificationCode;
            GUID  InterfaceGuid;
            DWORD dwDataSize;
            PVOID pData;
        }
        """
        if actual.NotificationSource not in WLAN_NOTIFICATION_SOURCE_DICT:
            return None

        codes = WlanEvent.ns_type_to_codes_dict[actual.NotificationSource]

        if codes != None:
            try:
                code = codes(actual.NotificationCode)
                data = WlanEvent.parse_data(actual.pData, actual.dwDataSize, actual.NotificationSource, code)
                if isinstance(data, WLAN_MSM_NOTIFICATION_DATA):
                    data = MSMNotificationData(data)
                if isinstance(data, WLAN_CONNECTION_NOTIFICATION_DATA):
                    data = ACMConnectionNotificationData(data)

                event = WlanEvent(actual,
                                  WLAN_NOTIFICATION_SOURCE_DICT[actual.NotificationSource],
                                  code.name,
                                  actual.InterfaceGuid,
                                  data)
                return event
            except:
                return None

    @staticmethod
    def parse_data(data_pointer, data_size, source, code):
        if data_size == 0 or (source != WLAN_NOTIFICATION_SOURCE_MSM and source != WLAN_NOTIFICATION_SOURCE_ACM):
            return None

        if source == WLAN_NOTIFICATION_SOURCE_MSM:
            typ = WLAN_NOTIFICATION_DATA_MSM_TYPES_DICT[code]
        elif source == WLAN_NOTIFICATION_SOURCE_ACM:
            typ = WLAN_NOTIFICATION_DATA_ACM_TYPES_DICT[code]
        else:
            return None

        if typ is None:
            return None

        return WlanEvent.deref(data_pointer, typ)

    @staticmethod
    def deref(addr, typ):
        return (typ).from_address(addr)

    def __str__(self):
        return self.notificationCode


def OnWlanNotification(callback, wlan_notification_data, context):
    event = WlanEvent.from_wlan_notification_data(wlan_notification_data)

    if event != None:
        callback(event, context)


global_callbacks = []
global_handles = []


class NotificationObject(object):
    def __init__(self, handle, callback):
        self.handle = handle
        self.callback = callback


def registerNotification(callback, context=None):
    handle = WlanOpenHandle()

    c_back = WlanRegisterNotification(handle, functools.partial(OnWlanNotification, callback), context)
    global_callbacks.append(c_back)
    global_handles.append(handle)

    return NotificationObject(handle, c_back)


def unregisterNotification(notification_object):
    # TODO: Instead of enumerating on the global lists, just save
    # the NotificationObject-s in some list or dict.
    WlanCloseHandle(notification_object.handle)

    for i, h in enumerate(global_handles):
        if h == notification_object.handle:
            del global_handles[i]

    for i, c in enumerate(global_callbacks):
        if c == notification_object.callback:
            del global_callbacks[i]


def unregisterAllNotifications():
    for handle in global_handles:
        WlanCloseHandle(handle)
    del global_handles[:]
    del global_callbacks[:]
