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
from typing import List, Dict, Optional, Any, Tuple
import xmltodict

from comtypes import GUID
from win32wifi.Win32NativeWifiApi import *

NULL = None

class WlanHandle:
    """Context manager for WLAN handles."""
    def __init__(self):
        self.handle = None

    def __enter__(self) -> HANDLE:
        self.handle = WlanOpenHandle()
        return self.handle

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.handle:
            WlanCloseHandle(self.handle)

class WirelessInterface:
    def __init__(self, wlan_iface_info: WLAN_INTERFACE_INFO):
        self.description: str = wlan_iface_info.strInterfaceDescription
        self.guid: GUID = GUID(wlan_iface_info.InterfaceGuid)
        self.guid_string: str = str(wlan_iface_info.InterfaceGuid)
        self.state: int = wlan_iface_info.isState
        self.state_string: str = WLAN_INTERFACE_STATE_DICT[self.state]

    def __str__(self) -> str:
        return (f"Description: {self.description}\n"
                f"GUID: {self.guid}\n"
                f"State: {self.state_string}")


class InformationElement:
    def __init__(self, element_id: int, length: int, body: bytes):
        self.element_id = element_id
        self.length = length
        self.body = body

    def __str__(self) -> str:
        return (f"Element ID: {self.element_id}\n"
                f"Length: {self.length}\n"
                f"Body: {self.body!r}")


class WirelessNetwork:
    def __init__(self, wireless_network: WLAN_AVAILABLE_NETWORK):
        self.ssid: bytes = wireless_network.dot11Ssid.SSID[:wireless_network.dot11Ssid.SSIDLength]
        self.profile_name: str = wireless_network.ProfileName
        self.bss_type: str = DOT11_BSS_TYPE_DICT_KV[wireless_network.dot11BssType]
        self.number_of_bssids: int = wireless_network.NumberOfBssids
        self.connectable: bool = bool(wireless_network.NetworkConnectable)
        self.number_of_phy_types: int = wireless_network.NumberOfPhyTypes
        self.signal_quality: int = wireless_network.wlanSignalQuality
        self.security_enabled: bool = bool(wireless_network.SecurityEnabled)
        auth = wireless_network.dot11DefaultAuthAlgorithm
        self.auth: str = DOT11_AUTH_ALGORITHM_DICT[auth]
        cipher = wireless_network.dot11DefaultCipherAlgorithm
        self.cipher: str = DOT11_CIPHER_ALGORITHM_DICT[cipher]
        self.flags: int = wireless_network.Flags

    def __str__(self) -> str:
        profile = self.profile_name if self.profile_name else "<No Profile>"
        return (f"Profile Name: {profile}\n"
                f"SSID: {self.ssid.decode('utf-8', 'replace')}\n"
                f"BSS Type: {self.bss_type}\n"
                f"Number of BSSIDs: {self.number_of_bssids}\n"
                f"Connectable: {self.connectable}\n"
                f"Number of PHY types: {self.number_of_phy_types}\n"
                f"Signal Quality: {self.signal_quality}%\n"
                f"Security Enabled: {self.security_enabled}\n"
                f"Authentication: {self.auth}\n"
                f"Cipher: {self.cipher}\n"
                f"Flags: {self.flags}")


class WirelessNetworkBss:
    def __init__(self, bss_entry: WLAN_BSS_ENTRY):
        self.ssid: bytes = bss_entry.dot11Ssid.SSID[:bss_entry.dot11Ssid.SSIDLength]
        self.link_quality: int = bss_entry.LinkQuality
        self.bssid: str = ":".join(f"{x:02X}" for x in bss_entry.dot11Bssid)
        self.bss_type: str = DOT11_BSS_TYPE_DICT_KV[bss_entry.dot11BssType]
        self.phy_type: str = DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType]
        self.rssi: int = bss_entry.Rssi
        self.ch_center_frequency: int = bss_entry.ChCenterFrequency
        self.capabilities: int = bss_entry.CapabilityInformation
        self.raw_information_elements: List[int] = []
        self.information_elements: List[InformationElement] = []
        self.__process_information_elements(bss_entry)
        self.__process_information_elements2()

    def __process_information_elements(self, bss_entry: WLAN_BSS_ENTRY):
        bss_entry_pointer = addressof(bss_entry)
        ie_offset = bss_entry.IeOffset
        data_type = (c_ubyte * bss_entry.IeSize)
        ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
        self.raw_information_elements = list(ie_buffer)

    def __process_information_elements2(self):
        MINIMAL_IE_SIZE = 2
        aux = self.raw_information_elements
        index = 0
        while index < len(aux) - MINIMAL_IE_SIZE:
            eid = aux[index]
            index += 1
            length = aux[index]
            index += 1
            body = bytes(aux[index : index + length])
            index += length
            ie = InformationElement(eid, length, body)
            self.information_elements.append(ie)

    def __str__(self) -> str:
        result = (f"BSSID: {self.bssid}\n"
                  f"SSID: {self.ssid.decode('utf-8', 'replace')}\n"
                  f"Link Quality: {self.link_quality}%\n"
                  f"BSS Type: {self.bss_type}\n"
                  f"PHY Type: {self.phy_type}\n"
                  f"Capabilities: {self.capabilities}\n"
                  "\nInformation Elements:\n")
        for ie in self.information_elements:
            lines = str(ie).split("\n")
            for line in lines:
                result += f" + {line}\n"
            result += "\n"
        return result


class WirelessProfile:
    def __init__(self, wireless_profile: WLAN_PROFILE_INFO, xml: str):
        self.name: str = wireless_profile.ProfileName
        self.flags: int = wireless_profile.Flags
        self.xml: str = xml
        self.ssid: Optional[str] = None
        self._parse_xml(self.xml)

    def _parse_xml(self, xml: str):
        try:
            d = xmltodict.parse(xml)
            self.ssid = d['WLANProfile']['SSIDConfig']['SSID']['name']
        except Exception:
            self.ssid = None

    def __str__(self) -> str:
        return (f"Profile Name: {self.name}\n"
                f"Flags: {self.flags}\n"
                f"XML:\n{self.xml}")


class MSMNotificationData:
    def __init__(self, msm_notification_data: WLAN_MSM_NOTIFICATION_DATA):
        self.connection_mode: str = WLAN_CONNECTION_MODE_KV[msm_notification_data.wlanConnectionMode]
        self.profile_name: str = msm_notification_data.strProfileName
        self.ssid: bytes = msm_notification_data.dot11Ssid.SSID[:msm_notification_data.dot11Ssid.SSIDLength]
        self.bss_type: str = DOT11_BSS_TYPE_DICT_KV[msm_notification_data.dot11BssType]
        self.mac_addr: str = ":".join(f"{x:02x}" for x in msm_notification_data.dot11MacAddr[:6])

    def __str__(self) -> str:
        return (f"Connection Mode: {self.connection_mode}\n"
                f"Profile Name: {self.profile_name}\n"
                f"SSID: {self.ssid.decode('utf-8', 'replace')}\n"
                f"BSS Type: {self.bss_type}\n"
                f"MAC: {self.mac_addr}")

class ACMConnectionNotificationData:
    def __init__(self, acm_notification_data: WLAN_CONNECTION_NOTIFICATION_DATA):
        self.connection_mode: str = WLAN_CONNECTION_MODE_KV[acm_notification_data.wlanConnectionMode]
        self.profile_name: str = acm_notification_data.strProfileName
        self.ssid: bytes = acm_notification_data.dot11Ssid.SSID[:acm_notification_data.dot11Ssid.SSIDLength]
        self.bss_type: str = DOT11_BSS_TYPE_DICT_KV[acm_notification_data.dot11BssType]
        self.security_enabled: bool = bool(acm_notification_data.bSecurityEnabled)

    def __str__(self) -> str:
        return (f"Connection Mode: {self.connection_mode}\n"
                f"Profile Name: {self.profile_name}\n"
                f"SSID: {self.ssid.decode('utf-8', 'replace')}\n"
                f"BSS Type: {self.bss_type}\n"
                f"Security Enabled: {self.security_enabled}")

class WirelessInterfaceCapability:
    def __init__(self, capability: WLAN_INTERFACE_CAPABILITY):
        self.interface_type: int = capability.interfaceType
        self.dot11_connection_supported: bool = bool(capability.bDot11ConnectionSupported)
        self.max_desired_bssid_list_size: int = capability.dwMaxDesiredBssidListSize
        self.max_desired_ssid_list_size: int = capability.dwMaxDesiredSsidListSize
        self.number_of_supported_phys: int = capability.dwNumberOfSupportedPhys
        self.phy_types: List[str] = [
            DOT11_PHY_TYPE_DICT[capability.dot11PhyTypes[i]]
            for i in range(self.number_of_supported_phys)
        ]

    def __str__(self) -> str:
        return (f"Dot11 Connection Supported: {self.dot11_connection_supported}\n"
                f"Max BSSID List Size: {self.max_desired_bssid_list_size}\n"
                f"Max SSID List Size: {self.max_desired_ssid_list_size}\n"
                f"Supported PHY Types: {', '.join(self.phy_types)}")

def getWirelessInterfaces() -> List[WirelessInterface]:
    """Returns a list of WirelessInterface objects based on the wireless
       interfaces available."""
    interfaces_list = []
    with WlanHandle() as handle:
        wlan_ifaces = WlanEnumInterfaces(handle)
        try:
            # Handle the WLAN_INTERFACE_INFO_LIST pointer to get a list of
            # WLAN_INTERFACE_INFO structures.
            data_type = wlan_ifaces.contents.InterfaceInfo._type_
            num = wlan_ifaces.contents.NumberOfItems
            ifaces_pointer = addressof(wlan_ifaces.contents.InterfaceInfo)
            wlan_interface_info_list = (data_type * num).from_address(ifaces_pointer)
            for wlan_interface_info in wlan_interface_info_list:
                wlan_iface = WirelessInterface(wlan_interface_info)
                interfaces_list.append(wlan_iface)
        finally:
            WlanFreeMemory(wlan_ifaces)
    return interfaces_list


def getWirelessNetworkBssList(wireless_interface: WirelessInterface) -> List[WirelessNetworkBss]:
    """Returns a list of WirelessNetworkBss objects based on the wireless
       networks availables."""
    networks = []
    with WlanHandle() as handle:
        bss_list = WlanGetNetworkBssList(handle, wireless_interface.guid)
        try:
            # Handle the WLAN_BSS_LIST pointer to get a list of WLAN_BSS_ENTRY
            # structures.
            data_type = bss_list.contents.wlanBssEntries._type_
            num = bss_list.contents.NumberOfItems
            bsss_pointer = addressof(bss_list.contents.wlanBssEntries)
            bss_entries_list = (data_type * num).from_address(bsss_pointer)
            for bss_entry in bss_entries_list:
                networks.append(WirelessNetworkBss(bss_entry))
        finally:
            WlanFreeMemory(bss_list)
    return networks


def getWirelessAvailableNetworkList(wireless_interface: WirelessInterface) -> List[WirelessNetwork]:
    """Returns a list of WirelessNetwork objects based on the wireless
       networks availables."""
    networks = []
    with WlanHandle() as handle:
        network_list = WlanGetAvailableNetworkList(handle, wireless_interface.guid)
        try:
            # Handle the WLAN_AVAILABLE_NETWORK_LIST pointer to get a list of
            # WLAN_AVAILABLE_NETWORK structures.
            data_type = network_list.contents.Network._type_
            num = network_list.contents.NumberOfItems
            network_pointer = addressof(network_list.contents.Network)
            networks_list = (data_type * num).from_address(network_pointer)

            for network in networks_list:
                networks.append(WirelessNetwork(network))
        finally:
            WlanFreeMemory(network_list)
    return networks


def getWirelessProfileXML(wireless_interface: WirelessInterface, profile_name: str) -> str:
    with WlanHandle() as handle:
        xml_data = WlanGetProfile(handle,
                                  wireless_interface.guid,
                                  profile_name)
        try:
            xml = xml_data.value
        finally:
            WlanFreeMemory(xml_data)
    return xml


def getWirelessProfiles(wireless_interface: WirelessInterface) -> List[WirelessProfile]:
    """Returns a list of WirelessProfile objects based on the wireless
       profiles."""
    profiles = []
    with WlanHandle() as handle:
        profile_list = WlanGetProfileList(handle, wireless_interface.guid)
        try:
            # Handle the WLAN_PROFILE_INFO_LIST pointer to get a list of
            # WLAN_PROFILE_INFO structures.
            data_type = profile_list.contents.ProfileInfo._type_
            num = profile_list.contents.NumberOfItems
            profile_info_pointer = addressof(profile_list.contents.ProfileInfo)
            profiles_list = (data_type * num).from_address(profile_info_pointer)
            for profile in profiles_list:
                xml_data = WlanGetProfile(handle,
                                          wireless_interface.guid,
                                          profile.ProfileName)
                try:
                    profiles.append(WirelessProfile(profile, xml_data.value))
                finally:
                    WlanFreeMemory(xml_data)
        finally:
            WlanFreeMemory(profile_list)
    return profiles

def deleteProfile(wireless_interface: WirelessInterface, profile_name: str) -> int:
    with WlanHandle() as handle:
        result = WlanDeleteProfile(handle, wireless_interface.guid, profile_name)
    return result

def disconnect(wireless_interface: WirelessInterface) -> None:
    with WlanHandle() as handle:
        WlanDisconnect(handle, wireless_interface.guid)

def setProfile(wireless_interface: WirelessInterface, profile_xml: str, dwFlags: int = 0, bOverwrite: bool = True) -> int:
    with WlanHandle() as handle:
        result = WlanSetProfile(handle, wireless_interface.guid, dwFlags, profile_xml, bOverwrite=bOverwrite)
    return result

def getReasonCodeString(reason_code: int) -> str:
    return WlanReasonCodeToString(reason_code)

def getInterfaceCapability(wireless_interface: WirelessInterface) -> WirelessInterfaceCapability:
    with WlanHandle() as handle:
        cap_ptr = WlanGetInterfaceCapability(handle, wireless_interface.guid)
        try:
            return WirelessInterfaceCapability(cap_ptr.contents)
        finally:
            WlanFreeMemory(cap_ptr)

def connect(wireless_interface: WirelessInterface, connection_params: Dict[str, Any]) -> int:
    """
        The WlanConnect function attempts to connect to a specific network.

        connection_params should be a dict with this structure:
        { "connectionMode": "valid connection mode string",
          "profile": ("profile name string" | "profile xml" | None),
          "ssid": "ssid string" | None,
          "bssidList": [ "desired bssid string", ... ] | None,
          "bssType": "valid bss type string",
          "flags": valid flag dword (int) }
    """
    with WlanHandle() as handle:
        cnxp = WLAN_CONNECTION_PARAMETERS()
        connection_mode = connection_params["connectionMode"]
        connection_mode_int = WLAN_CONNECTION_MODE_VK[connection_mode]
        cnxp.wlanConnectionMode = WLAN_CONNECTION_MODE(connection_mode_int)

        # determine strProfile
        profile = connection_params.get("profile")
        if connection_mode in ['wlan_connection_mode_profile', 'wlan_connection_mode_temporary_profile']:
            if profile is None:
                raise Win32WifiError(f"Profile is required for {connection_mode}", 87)
            cnxp.strProfile = LPCWSTR(profile)
        else:
            cnxp.strProfile = cast(None, LPCWSTR)

        # ssid
        ssid = connection_params.get("ssid")
        dot11_ssid_ptr = None
        if ssid is not None:
            dot11Ssid = DOT11_SSID()
            ssid_bytes = ssid.encode('utf-8')
            dot11Ssid.SSIDLength = len(ssid_bytes)
            dot11Ssid.SSID = ssid_bytes
            dot11_ssid_ptr = pointer(dot11Ssid)
        cnxp.pDot11_ssid = dot11_ssid_ptr

        # bssidList
        bssid_list_ptr = None
        bssid_list = connection_params.get("bssidList")
        if bssid_list is not None:
            num_entries = len(bssid_list)
            # Dynamic structure for DOT11_BSSID_LIST
            class DYNAMIC_DOT11_BSSID_LIST(Structure):
                _fields_ = [("Header", NDIS_OBJECT_HEADER),
                            ("uNumOfEntries", c_ulong),
                            ("uTotalNumOfEntries", c_ulong),
                            ("BSSIDs", DOT11_MAC_ADDRESS * num_entries)]

            bssidList = DYNAMIC_DOT11_BSSID_LIST()
            bssidList.Header.Type = bytes([NDIS_OBJECT_TYPE_DEFAULT])
            bssidList.Header.Revision = bytes([DOT11_BSSID_LIST_REVISION_1])
            bssidList.Header.Size = sizeof(DYNAMIC_DOT11_BSSID_LIST)
            bssidList.uNumOfEntries = num_entries
            bssidList.uTotalNumOfEntries = num_entries
            for i, bssid_str in enumerate(bssid_list):
                mac = [int(x, 16) for x in bssid_str.split(':')]
                bssidList.BSSIDs[i] = (c_ubyte * 6)(*mac)
            bssid_list_ptr = cast(pointer(bssidList), POINTER(DOT11_BSSID_LIST))
        cnxp.pDesiredBssidList = bssid_list_ptr

        # bssType
        bss_type_str = connection_params["bssType"]
        bss_type_int = DOT11_BSS_TYPE_DICT_VK[bss_type_str]
        cnxp.dot11BssType = DOT11_BSS_TYPE(bss_type_int)

        # flags
        cnxp.dwFlags = DWORD(connection_params.get("flags", 0))

        result = WlanConnect(handle, wireless_interface.guid, cnxp)
    return result

def dot11bssidToString(dot11Bssid: DOT11_MAC_ADDRESS) -> str:
    return ":".join(f"{x:02X}" for x in dot11Bssid)

def queryInterface(wireless_interface: WirelessInterface, opcode_item: str) -> Tuple[Any, Any]:
    """
    Queries various parameters of a specified interface.
    opcode_item is a string like "interface_state" or "current_connection".
    """
    opcode_item_ext = f"wlan_intf_opcode_{opcode_item}"
    opcode_val = None
    for key, val in WLAN_INTF_OPCODE_DICT.items():
        if val == opcode_item_ext:
            opcode_val = key
            break
    
    if opcode_val is None:
        raise ValueError(f"Unknown opcode item: {opcode_item}")

    with WlanHandle() as handle:
        result_ptr = WlanQueryInterface(handle, wireless_interface.guid, WLAN_INTF_OPCODE(opcode_val))
        try:
            r = result_ptr.contents
            if opcode_item == "interface_state":
                ext_out = WLAN_INTERFACE_STATE_DICT[r.value]
            elif opcode_item == "current_connection":
                isState = WLAN_INTERFACE_STATE_DICT[r.isState]
                wlanConnectionMode = WLAN_CONNECTION_MODE_KV[r.wlanConnectionMode]
                strProfileName = r.strProfileName
                aa = r.wlanAssociationAttributes
                wlanAssociationAttributes = {
                    "dot11Ssid": aa.dot11Ssid.SSID[:aa.dot11Ssid.SSIDLength],
                    "dot11BssType": DOT11_BSS_TYPE_DICT_KV[aa.dot11BssType],
                    "dot11Bssid": dot11bssidToString(aa.dot11Bssid),
                    "dot11PhyType": DOT11_PHY_TYPE_DICT[aa.dot11PhyType],
                    "uDot11PhyIndex": aa.uDot11PhyIndex,
                    "wlanSignalQuality": aa.wlanSignalQuality,
                    "ulRxRate": aa.ulRxRate,
                    "ulTxRate": aa.ulTxRate,
                }
                sa = r.wlanSecurityAttributes
                wlanSecurityAttributes = {
                    "bSecurityEnabled": bool(sa.bSecurityEnabled),
                    "bOneXEnabled": bool(sa.bOneXEnabled),
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
                ext_out = r.value if hasattr(r, 'value') else r
            
            # Create a copy of the data before freeing the memory
            # For simplicity in this wrapper, we return the ext_out which is a plain Python dict/string/val
            return None, ext_out # The raw 'r' is about to be freed, we should probably not return it.
        finally:
            WlanFreeMemory(result_ptr)


class WlanEvent:
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

    def __init__(self, original: WLAN_NOTIFICATION_DATA, notificationSource: str, notificationCode: str, interfaceGuid: GUID, data: Any):
        self.original = original
        self.notificationSource = notificationSource
        self.notificationCode = notificationCode
        self.interfaceGuid = interfaceGuid
        self.data = data

    @staticmethod
    def from_wlan_notification_data(wnd_ptr: POINTER(WLAN_NOTIFICATION_DATA)) -> Optional['WlanEvent']:
        actual = wnd_ptr.contents
        if actual.NotificationSource not in WLAN_NOTIFICATION_SOURCE_DICT:
            return None

        codes = WlanEvent.ns_type_to_codes_dict.get(actual.NotificationSource)
        if codes is not None:
            try:
                code = codes(actual.NotificationCode)
                data = WlanEvent.parse_data(actual.pData, actual.dwDataSize, actual.NotificationSource, code)
                if isinstance(data, WLAN_MSM_NOTIFICATION_DATA):
                    data = MSMNotificationData(data)
                elif isinstance(data, WLAN_CONNECTION_NOTIFICATION_DATA):
                    data = ACMConnectionNotificationData(data)

                return WlanEvent(actual,
                                 WLAN_NOTIFICATION_SOURCE_DICT[actual.NotificationSource],
                                 code.name,
                                 actual.InterfaceGuid,
                                 data)
            except Exception:
                return None
        return None

    @staticmethod
    def parse_data(data_pointer: int, data_size: int, source: int, code: Enum) -> Any:
        if data_size == 0 or (source != WLAN_NOTIFICATION_SOURCE_MSM and source != WLAN_NOTIFICATION_SOURCE_ACM):
            return None

        typ = None
        if source == WLAN_NOTIFICATION_SOURCE_MSM:
            typ = WLAN_NOTIFICATION_DATA_MSM_TYPES_DICT.get(code)
        elif source == WLAN_NOTIFICATION_SOURCE_ACM:
            typ = WLAN_NOTIFICATION_DATA_ACM_TYPES_DICT.get(code)

        if typ is None:
            return None

        return (typ).from_address(data_pointer)

    def __str__(self) -> str:
        return f"{self.notificationSource}: {self.notificationCode}"


def OnWlanNotification(callback, wlan_notification_data, context):
    event = WlanEvent.from_wlan_notification_data(wlan_notification_data)
    if event is not None:
        callback(event, context)


global_callbacks = []
global_handles = []


class NotificationObject:
    def __init__(self, handle: HANDLE, callback: Any):
        self.handle = handle
        self.callback = callback


def registerNotification(callback: Any, context: Any = None) -> NotificationObject:
    handle = WlanOpenHandle()
    c_back = WlanRegisterNotification(handle, functools.partial(OnWlanNotification, callback), context)
    global_callbacks.append(c_back)
    global_handles.append(handle)
    return NotificationObject(handle, c_back)


def unregisterNotification(notification_object: NotificationObject) -> None:
    if notification_object.handle in global_handles:
        WlanCloseHandle(notification_object.handle)
        global_handles.remove(notification_object.handle)
    if notification_object.callback in global_callbacks:
        global_callbacks.remove(notification_object.callback)


def unregisterAllNotifications() -> None:
    for handle in global_handles:
        try:
            WlanCloseHandle(handle)
        except Exception:
            pass
    global_handles.clear()
    global_callbacks.clear()
