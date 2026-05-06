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

import sys

from win32wifi.Win32Wifi import Win32WifiError, deleteProfile, getWirelessInterfaces, getWirelessProfiles


def listProfiles(iface):
    profiles = getWirelessProfiles(iface)
    for profile in profiles:
        print(profile.name)
        print("-" * 20)


def delProfile(iface, profile_name):
    try:
        deleteProfile(iface, profile_name)
        print(f"Profile '{profile_name}' deleted successfully.")
    except Win32WifiError as e:
        if e.error_code == 1168:
            print(f"Profile '{profile_name}' does not exist.")
        else:
            print(f"Failed to delete profile '{profile_name}': {e}")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("Usage: python delete_profile.py [profile_name]")
        sys.exit(1)

    ifaces = getWirelessInterfaces()

    for iface in ifaces:
        if len(sys.argv) < 2:
            # No profile name. Just list available profiles.
            listProfiles(iface)
        else:
            # Delete the given profile.
            delProfile(iface, sys.argv[1])
