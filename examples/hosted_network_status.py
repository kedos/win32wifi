# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - 2024 Shaked Gitelman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Author: Shaked Gitelman   (almondg)   <shaked.dev@gmail.com>
#

from win32wifi import Win32Wifi

if __name__ == "__main__":
    try:
        print("Querying Hosted Network (SoftAP) status...")
        status = Win32Wifi.hostedNetworkQueryStatus()
        print(status)

        if status.state == "wlan_hosted_network_active":
            print("\nSecondary Key Info:")
            key_info = Win32Wifi.hostedNetworkQuerySecondaryKey()
            print(f"  Key: {key_info['key'].decode()}")
            print(f"  Is Passphrase: {key_info['is_passphrase']}")
            print(f"  Is Persistent: {key_info['is_persistent']}")

    except Exception as e:
        print(f"Error: {e}")
        print("Note: Hosted Network may not be supported by your wireless driver.")
