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

from win32wifi.Win32Wifi import getInterfaceCapability, getWirelessInterfaces

if __name__ == "__main__":
    ifaces = getWirelessInterfaces()
    print(f"Found {len(ifaces)} wireless interface(s).")
    for iface in ifaces:
        print(f"Interface: {iface.description}")
        try:
            capabilities = getInterfaceCapability(iface)
            print("Capabilities:")
            print(capabilities)
        except Exception as e:
            print(f"  Error getting capabilities: {e}")
        print("-" * 20)
