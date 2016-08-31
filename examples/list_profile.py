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

from win32wifi.Win32Wifi import getWirelessInterfaces
from win32wifi.Win32Wifi import getWirelessProfiles

if __name__ == "__main__":
    ifaces = getWirelessInterfaces()
    for iface in ifaces:
        print(iface)
        guid = iface.guid
        profiles = getWirelessProfiles(iface)
        print(profiles)
        for profile in profiles:
            if profile.name == "Pretty Fly for a WiFi":
                print("Deleting profile (%s)" % profile.name)
            print(profile.name)
            # print(profile)
            # print(type(profile))
            print("-" * 20)
        print()
