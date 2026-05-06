import unittest
from unittest.mock import MagicMock, patch, PropertyMock
import ctypes
from comtypes import GUID
from win32wifi import Win32NativeWifiApi, Win32Wifi

class TestMockedWin32Wifi(unittest.TestCase):

    @patch('win32wifi.Win32NativeWifiApi.wlanapi')
    def test_wlan_open_handle(self, mock_wlanapi):
        # Setup mock
        mock_wlanapi.WlanOpenHandle.return_value = 0 # ERROR_SUCCESS
        
        # We need to simulate the side effect of writing to the pointers
        def side_effect(version, reserved, p_negotiated, p_handle):
            p_negotiated.contents.value = 2
            p_handle.contents.value = 12345
            return 0
        
        mock_wlanapi.WlanOpenHandle.side_effect = side_effect
        
        handle = Win32NativeWifiApi.WlanOpenHandle()
        self.assertEqual(handle.value, 12345)
        mock_wlanapi.WlanOpenHandle.assert_called_once()

    @patch('win32wifi.Win32NativeWifiApi.wlanapi')
    def test_get_wireless_interfaces(self, mock_wlanapi):
        # Mock Open/Close/Enum
        mock_wlanapi.WlanOpenHandle.return_value = 0
        mock_wlanapi.WlanCloseHandle.return_value = 0
        mock_wlanapi.WlanEnumInterfaces.return_value = 0
        
        # Mock the interface list structure
        iface_list = Win32NativeWifiApi.WLAN_INTERFACE_INFO_LIST()
        iface_list.NumberOfItems = 1
        iface_list.Index = 0
        iface_list.InterfaceInfo[0].strInterfaceDescription = "Mock Interface"
        iface_list.InterfaceInfo[0].isState = 1 # connected
        
        def enum_side_effect(handle, reserved, pp_list):
            pp_list.contents = ctypes.pointer(iface_list)
            return 0
        
        mock_wlanapi.WlanEnumInterfaces.side_effect = enum_side_effect
        
        # Mock WlanFreeMemory to avoid errors on mock pointers
        mock_wlanapi.WlanFreeMemory.return_value = None

        with patch('win32wifi.Win32Wifi.WlanOpenHandle', return_value=ctypes.c_void_p(123)):
            interfaces = Win32Wifi.getWirelessInterfaces()
            
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].description, "Mock Interface")
        self.assertEqual(interfaces[0].state_string, "wlan_interface_state_connected")

    @patch('win32wifi.Win32NativeWifiApi.wlanapi')
    def test_connect_params_packing(self, mock_wlanapi):
        """Verify that the connect function packs parameters correctly."""
        mock_wlanapi.WlanConnect.return_value = 0
        
        iface = MagicMock(spec=Win32Wifi.WirelessInterface)
        iface.guid = GUID()
        
        params = {
            "connectionMode": "wlan_connection_mode_profile",
            "profile": "MyProfile",
            "ssid": "MySSID",
            "bssType": "dot11_BSS_type_infrastructure",
            "flags": 0
        }
        
        with patch('win32wifi.Win32Wifi.WlanOpenHandle', return_value=ctypes.c_void_p(123)):
            Win32Wifi.connect(iface, params)
            
        # Verify WlanConnect was called
        self.assertTrue(mock_wlanapi.WlanConnect.called)
        args = mock_wlanapi.WlanConnect.call_args[0]
        
        # args[2] is the POINTER(WLAN_CONNECTION_PARAMETERS)
        packed_params = args[2].contents
        self.assertEqual(packed_params.strProfile, "MyProfile")
        self.assertEqual(packed_params.pDot11_ssid.contents.SSID[:packed_params.pDot11_ssid.contents.SSIDLength].decode(), "MySSID")

    @patch('win32wifi.Win32NativeWifiApi.wlanapi')
    def test_error_handling(self, mock_wlanapi):
        """Verify that Win32WifiError is raised on failure."""
        mock_wlanapi.WlanOpenHandle.return_value = 87 # ERROR_INVALID_PARAMETER
        
        with self.assertRaises(Win32NativeWifiApi.Win32WifiError) as cm:
            Win32NativeWifiApi.WlanOpenHandle()
            
        self.assertEqual(cm.exception.error_code, 87)
        self.assertIn("Error Code: 87", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
