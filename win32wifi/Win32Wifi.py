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

import functools
import logging
import threading
import warnings
from ctypes import *
from typing import Any, Dict, List, Optional, Tuple

import xmltodict

from win32wifi.Win32NativeWifiApi import *

# Reuse whichever GUID the low-level module ended up with (real comtypes on
# Windows, ctypes fallback elsewhere) so both layers agree on the type.
from win32wifi.Win32NativeWifiApi import GUID

logger = logging.getLogger(__name__)

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
        data_type = c_ubyte * bss_entry.IeSize
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
        except (xmltodict.expat.ExpatError, KeyError, TypeError) as e:
            logger.debug("WirelessProfile %r: failed to extract SSID from XML: %s",
                         self.name, e)
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


class FilteredNetwork:
    def __init__(self, network: DOT11_NETWORK):
        self.ssid: bytes = network.dot11Ssid.SSID[:network.dot11Ssid.SSIDLength]
        self.bss_type: str = DOT11_BSS_TYPE_DICT_KV[network.dot11BssType]

    def __str__(self) -> str:
        return f"SSID: {self.ssid.decode('utf-8', 'replace')}, BSS Type: {self.bss_type}"


class HostedNetworkPeer:
    def __init__(self, peer_state: WLAN_HOSTED_NETWORK_PEER_STATE):
        self.mac_addr: str = ":".join(f"{x:02X}" for x in peer_state.PeerMacAddress)
        self.auth_state: int = peer_state.PeerAuthState

    def __str__(self) -> str:
        return f"MAC: {self.mac_addr}, Auth State: {self.auth_state}"


class HostedNetworkStatus:
    def __init__(self, status: WLAN_HOSTED_NETWORK_STATUS):
        self.state: str = WLAN_HOSTED_NETWORK_STATE_DICT[status.HostedNetworkState]
        self.ip_device_id: GUID = GUID(status.IPDeviceID)
        self.bssid: str = ":".join(f"{x:02X}" for x in status.wlanHostedNetworkBSSID)
        self.phy_type: str = DOT11_PHY_TYPE_DICT[status.dot11PhyType]
        self.channel_frequency: int = status.ulChannelFrequency
        self.number_of_peers: int = status.dwNumberOfPeers
        self.peers: List[HostedNetworkPeer] = []

        # Handle dynamic PeerList
        if self.number_of_peers > 0:
            data_type = WLAN_HOSTED_NETWORK_PEER_STATE
            num = self.number_of_peers
            peers_pointer = addressof(status.PeerList)
            peers_list = (data_type * num).from_address(peers_pointer)
            for peer in peers_list:
                self.peers.append(HostedNetworkPeer(peer))

    def __str__(self) -> str:
        peers_str = "\n".join(f" - {p}" for p in self.peers)
        return (f"State: {self.state}\n"
                f"IP Device ID: {self.ip_device_id}\n"
                f"BSSID: {self.bssid}\n"
                f"PHY Type: {self.phy_type}\n"
                f"Channel Frequency: {self.channel_frequency} kHz\n"
                f"Number of Peers: {self.number_of_peers}\n"
                f"Peers:\n{peers_str}")


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

def getFilterList(list_type: str) -> List[FilteredNetwork]:
    type_val = None
    for k, v in WLAN_FILTER_LIST_TYPE_DICT.items():
        if v == list_type:
            type_val = k
            break
    if type_val is None:
        raise ValueError(f"Unknown filter list type: {list_type}")

    networks = []
    with WlanHandle() as handle:
        filter_list_ptr = WlanGetFilterList(handle, type_val)
        try:
            fl = filter_list_ptr.contents
            # The structure has a fixed Network array of size 1, but it's actually dynamic
            data_type = DOT11_NETWORK
            num = fl.dwNumberOfItems
            networks_pointer = addressof(fl.Network)
            network_info_list = (data_type * num).from_address(networks_pointer)
            for net in network_info_list:
                networks.append(FilteredNetwork(net))
        finally:
            WlanFreeMemory(filter_list_ptr)
    return networks

def setFilterList(list_type: str, networks: List[Tuple[str, str]]) -> int:
    type_val = None
    for k, v in WLAN_FILTER_LIST_TYPE_DICT.items():
        if v == list_type:
            type_val = k
            break
    if type_val is None:
        raise ValueError(f"Unknown filter list type: {list_type}")

    num_items = len(networks)

    class DYNAMIC_WLAN_FILTER_LIST(Structure):
        _fields_ = [("dwNumberOfItems", DWORD),
                    ("dwIndex", DWORD),
                    ("Network", DOT11_NETWORK * num_items)]

    fl = DYNAMIC_WLAN_FILTER_LIST()
    fl.dwNumberOfItems = num_items
    fl.dwIndex = 0
    for i, (ssid, bss_type_str) in enumerate(networks):
        ssid_bytes = ssid.encode('utf-8')
        fl.Network[i].dot11Ssid.SSIDLength = len(ssid_bytes)
        fl.Network[i].dot11Ssid.SSID = ssid_bytes
        fl.Network[i].dot11BssType = DOT11_BSS_TYPE_DICT_VK[bss_type_str]

    with WlanHandle() as handle:
        result = WlanSetFilterList(handle, type_val, cast(pointer(fl), POINTER(WLAN_FILTER_LIST)))
    return result

def queryAutoConfigParameter(opcode: str) -> Any:
    opcode_val = None
    for k, v in WLAN_AUTOCONF_OPCODE_DICT.items():
        if v == opcode:
            opcode_val = k
            break
    if opcode_val is None:
        raise ValueError(f"Unknown autoconf opcode: {opcode}")

    with WlanHandle() as handle:
        data_ptr, data_size = WlanQueryAutoConfigParameter(handle, WLAN_AUTOCONF_OPCODE(opcode_val))
        try:
            # Most autoconf parameters are BOOL or DWORD
            if data_size == 4:
                return cast(data_ptr, POINTER(DWORD)).contents.value
            return data_ptr
        finally:
            WlanFreeMemory(data_ptr)

def setAutoConfigParameter(opcode: str, data: Any) -> int:
    opcode_val = None
    for k, v in WLAN_AUTOCONF_OPCODE_DICT.items():
        if v == opcode:
            opcode_val = k
            break
    if opcode_val is None:
        raise ValueError(f"Unknown autoconf opcode: {opcode}")

    if isinstance(data, bool):
        p_data = pointer(c_bool(data))
        data_size = sizeof(c_bool)
    elif isinstance(data, int):
        p_data = pointer(DWORD(data))
        data_size = sizeof(DWORD)
    else:
        p_data = data
        data_size = sizeof(data)

    with WlanHandle() as handle:
        result = WlanSetAutoConfigParameter(handle, WLAN_AUTOCONF_OPCODE(opcode_val), data_size, p_data)
    return result

def saveTemporaryProfile(
    wireless_interface: WirelessInterface,
    profile_name: str,
    all_user_security: Optional[str] = None,
    flags: int = 0,
    overwrite: bool = True,
) -> int:
    with WlanHandle() as handle:
        result = WlanSaveTemporaryProfile(
            handle,
            wireless_interface.guid,
            profile_name,
            all_user_security,
            flags,
            overwrite,
        )
    return result

def uiEditProfile(
    profile_name: str,
    wireless_interface: WirelessInterface,
    hwnd: int = 0,
    completion_source: str = "wlan_ui_completion_source_user",
) -> int:
    cs_val = None
    for k, v in WLAN_UI_COMPLETION_SOURCE_DICT.items():
        if v == completion_source:
            cs_val = k
            break
    if cs_val is None:
        raise ValueError(f"Unknown completion source: {completion_source}")

    # Client version 2 is for Vista or later
    result = WlanUIEditProfile(2, profile_name, wireless_interface.guid, hwnd, cs_val)
    return result

def renameProfile(wireless_interface: WirelessInterface, old_name: str, new_name: str) -> int:
    with WlanHandle() as handle:
        result = WlanRenameProfile(handle, wireless_interface.guid, old_name, new_name)
    return result

def setProfileEapUserData(
    wireless_interface: WirelessInterface,
    profile_name: str,
    eap_type_code: int,
    author_id: int,
    user_data: bytes,
    flags: int = 0,
) -> int:
    eap_method = EAP_METHOD_TYPE()
    eap_method.eapType.type = eap_type_code
    eap_method.eapType.dwVendorId = 0
    eap_method.eapType.dwVendorType = 0
    eap_method.dwAuthorId = author_id

    data_size = len(user_data)
    p_data = cast(create_string_buffer(user_data, data_size), c_void_p)

    with WlanHandle() as handle:
        result = WlanSetProfileEapUserData(handle, wireless_interface.guid, profile_name, eap_method, flags, data_size, p_data)
    return result

def setProfileEapXmlUserData(wireless_interface: WirelessInterface, profile_name: str, xml_user_data: str, flags: int = 0) -> int:
    with WlanHandle() as handle:
        result = WlanSetProfileEapXmlUserData(handle, wireless_interface.guid, profile_name, flags, xml_user_data)
    return result

def getSecuritySettings(securable_object: str) -> Dict[str, Any]:
    obj_val = None
    for k, v in WLAN_SECURABLE_OBJECT_DICT.items():
        if v == securable_object:
            obj_val = k
            break
    if obj_val is None:
        raise ValueError(f"Unknown securable object: {securable_object}")

    with WlanHandle() as handle:
        val_type, sddl, access = WlanGetSecuritySettings(handle, WLAN_SECURABLE_OBJECT(obj_val))
        return {
            "value_type": WLAN_OPCODE_VALUE_TYPE_DICT[val_type.value],
            "sddl": sddl,
            "granted_access": access
        }

def setSecuritySettings(securable_object: str, sddl: str) -> int:
    obj_val = None
    for k, v in WLAN_SECURABLE_OBJECT_DICT.items():
        if v == securable_object:
            obj_val = k
            break
    if obj_val is None:
        raise ValueError(f"Unknown securable object: {securable_object}")

    with WlanHandle() as handle:
        result = WlanSetSecuritySettings(handle, WLAN_SECURABLE_OBJECT(obj_val), sddl)
    return result

def getProfileCustomUserData(wireless_interface: WirelessInterface, profile_name: str) -> bytes:
    with WlanHandle() as handle:
        size, p_data = WlanGetProfileCustomUserData(handle, wireless_interface.guid, profile_name)
        try:
            return string_at(p_data, size)
        finally:
            WlanFreeMemory(p_data)

def setProfileCustomUserData(wireless_interface: WirelessInterface, profile_name: str, data: bytes) -> int:
    data_size = len(data)
    p_data = cast(create_string_buffer(data, data_size), c_void_p)
    with WlanHandle() as handle:
        result = WlanSetProfileCustomUserData(handle, wireless_interface.guid, profile_name, data_size, p_data)
    return result

def setProfileList(wireless_interface: WirelessInterface, profile_names: List[str]) -> int:
    num_items = len(profile_names)
    names_array = (LPCWSTR * num_items)(*profile_names)
    with WlanHandle() as handle:
        result = WlanSetProfileList(handle, wireless_interface.guid, num_items, names_array)
    return result

_HOSTED_NETWORK_DEPRECATION_MSG = (
    "Wlan Hosted Network APIs were removed by Microsoft in Windows 10 "
    "version 2004 and later. They will fail at runtime on modern Windows. "
    "Use the Mobile Hotspot APIs "
    "(Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager) "
    "via WinRT instead. This wrapper will be removed in a future release."
)


def _warn_hosted_network_deprecated() -> None:
    warnings.warn(
        _HOSTED_NETWORK_DEPRECATION_MSG,
        DeprecationWarning,
        stacklevel=3,
    )


def hostedNetworkForceStart() -> int:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        result = WlanHostedNetworkForceStart(handle)
    return result

def hostedNetworkForceStop() -> int:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        result = WlanHostedNetworkForceStop(handle)
    return result

def hostedNetworkInitSettings() -> int:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        result = WlanHostedNetworkInitSettings(handle)
    return result

def hostedNetworkQueryProperty(opcode: str) -> Any:
    _warn_hosted_network_deprecated()
    opcode_val = None
    for k, v in WLAN_HOSTED_NETWORK_OPCODE_DICT.items():
        if v == opcode:
            opcode_val = k
            break
    if opcode_val is None:
        raise ValueError(f"Unknown hosted network opcode: {opcode}")

    with WlanHandle() as handle:
        _size, p_data, _val_type = WlanHostedNetworkQueryProperty(
            handle, WLAN_HOSTED_NETWORK_OPCODE(opcode_val)
        )
        try:
            if opcode == "wlan_hosted_network_opcode_connection_settings":
                return cast(p_data, POINTER(WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS)).contents
            if opcode == "wlan_hosted_network_opcode_security_settings":
                return cast(p_data, POINTER(WLAN_HOSTED_NETWORK_SECURITY_SETTINGS)).contents
            if opcode == "wlan_hosted_network_opcode_enable":
                return cast(p_data, POINTER(BOOL)).contents.value
            return p_data
        finally:
            WlanFreeMemory(p_data)

def hostedNetworkQuerySecondaryKey() -> Dict[str, Any]:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        size, p_key, is_pass, is_pers = WlanHostedNetworkQuerySecondaryKey(handle)
        try:
            return {
                "key": string_at(p_key, size),
                "is_passphrase": is_pass,
                "is_persistent": is_pers
            }
        finally:
            WlanFreeMemory(p_key)

def hostedNetworkQueryStatus() -> HostedNetworkStatus:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        status_ptr = WlanHostedNetworkQueryStatus(handle)
        try:
            return HostedNetworkStatus(status_ptr.contents)
        finally:
            WlanFreeMemory(status_ptr)

def hostedNetworkRefreshSecuritySettings() -> int:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        result = WlanHostedNetworkRefreshSecuritySettings(handle)
    return result

def hostedNetworkSetProperty(opcode: str, data: Any) -> int:
    _warn_hosted_network_deprecated()
    opcode_val = None
    for k, v in WLAN_HOSTED_NETWORK_OPCODE_DICT.items():
        if v == opcode:
            opcode_val = k
            break
    if opcode_val is None:
        raise ValueError(f"Unknown hosted network opcode: {opcode}")

    if isinstance(data, bool):
        p_data = pointer(BOOL(data))
        data_size = sizeof(BOOL)
    elif hasattr(data, '_fields_'):
        p_data = pointer(data)
        data_size = sizeof(data)
    else:
        p_data = data
        data_size = 0

    with WlanHandle() as handle:
        result = WlanHostedNetworkSetProperty(handle, WLAN_HOSTED_NETWORK_OPCODE(opcode_val), data_size, p_data)
    return result

def hostedNetworkSetSecondaryKey(key: bytes, is_passphrase: bool = True, is_persistent: bool = True) -> int:
    _warn_hosted_network_deprecated()
    key_len = len(key)
    p_key = cast(create_string_buffer(key, key_len), c_char_p)
    with WlanHandle() as handle:
        result = WlanHostedNetworkSetSecondaryKey(handle, key_len, p_key, is_passphrase, is_persistent)
    return result

def hostedNetworkStartUsing() -> int:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        result = WlanHostedNetworkStartUsing(handle)
    return result

def hostedNetworkStopUsing() -> int:
    _warn_hosted_network_deprecated()
    with WlanHandle() as handle:
        result = WlanHostedNetworkStopUsing(handle)
    return result

def extractPsdIEDataList(ie_data: bytes, str_format: str) -> List[bytes]:
    data_size = len(ie_data)
    p_data = cast(create_string_buffer(ie_data, data_size), c_void_p)
    with WlanHandle() as handle:
        list_ptr = WlanExtractPsdIEDataList(handle, data_size, p_data, str_format)
        try:
            results = []
            num = list_ptr.contents.dwNumberOfItems
            # Dynamic access to RawData
            data_type = WLAN_RAW_DATA
            raw_pointer = addressof(list_ptr.contents.RawData)
            raw_list = (data_type * num).from_address(raw_pointer)
            for item in raw_list:
                results.append(string_at(item.DataBlob, item.DataSize))
            return results
        finally:
            WlanFreeMemory(list_ptr)

def setPsdIeDataList(str_format: Optional[str], data_list: List[bytes]) -> int:
    """Not implemented.

    Packing ``WLAN_RAW_DATA_LIST`` correctly requires a variable-length
    structure where each ``WLAN_RAW_DATA`` entry's ``DataBlob`` is sized
    per-item, plus careful alignment of the trailing payloads. The previous
    implementation silently dropped ``data_list`` and called the DLL with
    ``None`` — that produced wrong, undetectable results in production.
    Raise loudly until a real implementation lands; pull requests welcome.
    """
    raise NotImplementedError(
        "setPsdIeDataList is not implemented — variable-length WLAN_RAW_DATA "
        "packing has no caller-tested implementation in this library yet."
    )

def ihvControl(
    wireless_interface: WirelessInterface,
    control_type: str,
    in_buffer: bytes,
    out_buffer_size: int = 0,
) -> Tuple[int, bytes, int]:
    ct_val = None
    for k, v in WLAN_IHV_CONTROL_TYPE_DICT.items():
        if v == control_type:
            ct_val = k
            break
    if ct_val is None:
        raise ValueError(f"Unknown IHV control type: {control_type}")

    in_size = len(in_buffer)
    p_in = cast(create_string_buffer(in_buffer, in_size), c_void_p)

    with WlanHandle() as handle:
        res, p_out, returned = WlanIhvControl(
            handle,
            wireless_interface.guid,
            WLAN_IHV_CONTROL_TYPE(ct_val),
            in_size,
            p_in,
            out_buffer_size,
        )
        out_bytes = string_at(p_out, returned) if p_out else b""
    return res, out_bytes, returned

def deviceServiceCommand(
    wireless_interface: WirelessInterface,
    device_service_guid: GUID,
    opcode: int,
    in_buffer: bytes,
    out_buffer_size: int = 0,
) -> Tuple[int, bytes, int]:
    in_size = len(in_buffer)
    p_in = cast(create_string_buffer(in_buffer, in_size), c_void_p)

    with WlanHandle() as handle:
        res, p_out, returned = WlanDeviceServiceCommand(
            handle,
            wireless_interface.guid,
            device_service_guid,
            opcode,
            in_size,
            p_in,
            out_buffer_size,
        )
        out_bytes = string_at(p_out, returned) if p_out else b""
    return res, out_bytes, returned

def getSupportedDeviceServices(wireless_interface: WirelessInterface) -> List[GUID]:
    with WlanHandle() as handle:
        list_ptr = WlanGetSupportedDeviceServices(handle, wireless_interface.guid)
        try:
            results = []
            num = list_ptr.contents.dwNumberOfItems
            data_type = GUID
            guids_pointer = addressof(list_ptr.contents.DeviceServiceGuids)
            guid_list = (data_type * num).from_address(guids_pointer)
            for g in guid_list:
                results.append(GUID(g))
            return results
        finally:
            WlanFreeMemory(list_ptr)

def registerVirtualStationNotification(register: bool = True) -> int:
    with WlanHandle() as handle:
        result = WlanRegisterVirtualStationNotification(handle, register)
    return result

def setProfilePosition(wireless_interface: WirelessInterface, profile_name: str, position: int) -> int:
    with WlanHandle() as handle:
        result = WlanSetProfilePosition(handle, wireless_interface.guid, profile_name, position)
    return result

def setInterface(wireless_interface: WirelessInterface, opcode_item: str, data: Any) -> int:
    opcode_item_ext = f"wlan_intf_opcode_{opcode_item}"
    opcode_val = None
    for key, val in WLAN_INTF_OPCODE_DICT.items():
        if val == opcode_item_ext:
            opcode_val = key
            break

    if opcode_val is None:
        raise ValueError(f"Unknown opcode item: {opcode_item}")

    # For now, we only support basic types for setInterface (bool, dword)
    # If more complex structures are needed, they should be added here.
    if isinstance(data, bool):
        p_data = pointer(c_bool(data))
        data_size = sizeof(c_bool)
    elif isinstance(data, int):
        p_data = pointer(DWORD(data))
        data_size = sizeof(DWORD)
    else:
        # Fallback for already packed ctypes structures
        p_data = cast(pointer(data), c_void_p) if hasattr(data, '_fields_') else data
        data_size = sizeof(data) if hasattr(data, '_fields_') else 0

    with WlanHandle() as handle:
        result = WlanSetInterface(handle, wireless_interface.guid, WLAN_INTF_OPCODE(opcode_val), data_size, p_data)
    return result

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

def _decode_query_interface(opcode_item: str, r: Any) -> Any:
    """Pull a Pythonic value out of the WlanQueryInterface output.

    The native buffer is freed by the caller via WlanFreeMemory immediately
    after this returns, so every decoder MUST copy primitives/strings into
    plain Python objects — never return the ctypes object itself or a slice
    that shares its memory.
    """
    if opcode_item == "interface_state":
        return WLAN_INTERFACE_STATE_DICT[r.value]

    if opcode_item == "current_connection":
        aa = r.wlanAssociationAttributes
        sa = r.wlanSecurityAttributes
        return {
            "isState": WLAN_INTERFACE_STATE_DICT[r.isState],
            "wlanConnectionMode": WLAN_CONNECTION_MODE_KV[r.wlanConnectionMode],
            "strProfileName": str(r.strProfileName),
            "wlanAssociationAttributes": {
                "dot11Ssid": bytes(aa.dot11Ssid.SSID[:aa.dot11Ssid.SSIDLength]),
                "dot11BssType": DOT11_BSS_TYPE_DICT_KV[aa.dot11BssType],
                "dot11Bssid": dot11bssidToString(aa.dot11Bssid),
                "dot11PhyType": DOT11_PHY_TYPE_DICT[aa.dot11PhyType],
                "uDot11PhyIndex": int(aa.uDot11PhyIndex),
                "wlanSignalQuality": int(aa.wlanSignalQuality),
                "ulRxRate": int(aa.ulRxRate),
                "ulTxRate": int(aa.ulTxRate),
            },
            "wlanSecurityAttributes": {
                "bSecurityEnabled": bool(sa.bSecurityEnabled),
                "bOneXEnabled": bool(sa.bOneXEnabled),
                "dot11AuthAlgorithm": DOT11_AUTH_ALGORITHM_DICT[sa.dot11AuthAlgorithm],
                "dot11CipherAlgorithm": DOT11_CIPHER_ALGORITHM_DICT[sa.dot11CipherAlgorithm],
            },
        }

    if opcode_item == "radio_state":
        phys = []
        for i in range(int(r.dwNumberOfPhys)):
            phy = r.PhyRadioState[i]
            phys.append({
                "dwPhyIndex": int(phy.dwPhyIndex),
                "dot11SoftwareRadioState": DOT11_RADIO_STATE_DICT[phy.dot11SoftwareRadioState],
                "dot11HardwareRadioState": DOT11_RADIO_STATE_DICT[phy.dot11HardwareRadioState],
            })
        return phys

    if opcode_item == "bss_type":
        return DOT11_BSS_TYPE_DICT_KV[r.value]

    # Simple scalar opcodes — c_bool / c_long / c_ulong all expose `.value`.
    if hasattr(r, "value"):
        val = r.value
        # c_bool surfaces 0/1 as int on some platforms; coerce for consistency.
        if isinstance(val, int) and opcode_item in {
            "autoconf_enabled",
            "background_scan_enabled",
            "media_streaming_mode",
            "supported_safe_mode",
            "certified_safe_mode",
        }:
            return bool(val)
        return val

    raise ValueError(f"No decoder for opcode item: {opcode_item}")


def queryInterface(wireless_interface: WirelessInterface, opcode_item: str) -> Any:
    """Query a single attribute of a wireless interface.

    ``opcode_item`` is the suffix after ``wlan_intf_opcode_`` — e.g. ``rssi``,
    ``channel_number``, ``interface_state``, ``current_connection``,
    ``radio_state``. Returns a Pythonic value (``int``, ``bool``, ``str``,
    ``dict``, or ``list``) — never a ctypes object that points into the
    soon-to-be-freed native buffer.
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
            return _decode_query_interface(opcode_item, result_ptr.contents)
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
            except (ValueError, KeyError) as e:
                # ValueError → unknown NotificationCode for this source's enum;
                # KeyError → unknown source/code in the lookup tables. Either
                # is a stray notification we can safely drop.
                logger.debug("Dropping unknown WLAN notification (source=%s code=%s): %s",
                             actual.NotificationSource, actual.NotificationCode, e)
                return None
        return None

    @staticmethod
    def parse_data(data_pointer: int, data_size: int, source: int, code: Enum) -> Any:
        if data_size == 0 or source not in (WLAN_NOTIFICATION_SOURCE_MSM, WLAN_NOTIFICATION_SOURCE_ACM):
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


# Notification callbacks fire on Windows worker threads, so the bookkeeping
# below must be serialized. ``_notif_lock`` guards both lists; the lists hold
# strong references so the CFUNCTYPE trampolines stay alive until they're
# explicitly torn down.
_notif_lock = threading.Lock()
_notif_handles: List[HANDLE] = []
_notif_callbacks: List[Any] = []


class NotificationObject:
    def __init__(self, handle: HANDLE, callback: Any):
        self.handle = handle
        self.callback = callback


def registerNotification(callback: Any, context: Any = None) -> NotificationObject:
    handle = WlanOpenHandle()
    c_back = WlanRegisterNotification(handle, functools.partial(OnWlanNotification, callback), context)
    with _notif_lock:
        _notif_handles.append(handle)
        _notif_callbacks.append(c_back)
    return NotificationObject(handle, c_back)


def unregisterNotification(notification_object: NotificationObject) -> None:
    """Tear down a notification registration created by :func:`registerNotification`.

    Calls ``WlanRegisterNotification(handle, NULL, ...)`` per the Microsoft
    docs so the OS knows to stop firing callbacks, then closes the handle.
    Idempotent: calling twice on the same object is harmless.
    """
    with _notif_lock:
        try:
            _notif_handles.remove(notification_object.handle)
        except ValueError:
            return  # already torn down
        try:
            _notif_callbacks.remove(notification_object.callback)
        except ValueError:
            pass

    # Drop OS-side registration first so callbacks stop firing, then close
    # the handle. Order matters: closing the handle first risks a callback
    # arriving against a dead handle.
    try:
        WlanRegisterNotification(notification_object.handle, None, None)
    except Win32WifiError as e:
        logger.warning("Failed to deregister WLAN notification: %s", e)
    try:
        WlanCloseHandle(notification_object.handle)
    except Win32WifiError as e:
        logger.warning("Failed to close WLAN handle during unregister: %s", e)


def unregisterAllNotifications() -> None:
    """Tear down every outstanding notification registered with this module."""
    with _notif_lock:
        handles = list(_notif_handles)
        _notif_handles.clear()
        _notif_callbacks.clear()

    for handle in handles:
        try:
            WlanRegisterNotification(handle, None, None)
        except Win32WifiError as e:
            logger.warning("Failed to deregister WLAN notification: %s", e)
        try:
            WlanCloseHandle(handle)
        except Win32WifiError as e:
            logger.warning("Failed to close WLAN handle: %s", e)
