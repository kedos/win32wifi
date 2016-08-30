# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - Shaked Gitelman
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
# Author: Shaked Gitelman   (almondg)   <shaked.dev@gmail.com>
#

import sys

sys.path.append('../')

from Win32Wifi import deleteProfile
from Win32Wifi import getWirelessInterfaces
from Win32Wifi import getWirelessProfiles


def listProfiles(iface):
    guid = iface.guid
    profiles = getWirelessProfiles(iface)
    for profile in profiles:
        print(profile.name)
        print("-" * 20)

def delProfile(iface, profile_name):
    try:
        deleteProfile(iface, profile_name)
    except Exception as e:
        if e.args[1] == 1168:
            print("Profile '%s' does not exist." % profile_name)
        else:
            raise e
    

if __name__ == "__main__":

    if len(sys.argv) > 2:
        print("Usage: python delete_profile.py [profile_name]")
        exit(1)

    ifaces = getWirelessInterfaces()

    for iface in ifaces:    
        if len(sys.argv) < 2:
            # No profile name. Just list available profiles.
            listProfiles(iface)
        else:
            # Delete the given profile.
            delProfile(iface, sys.argv[1])
        