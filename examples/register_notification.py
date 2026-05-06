# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - 2024 Shaked Gitelman
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

import asyncio
from datetime import datetime

from win32wifi.Win32Wifi import getWirelessInterfaces, registerNotification


def demo(wlan_event, context):
    if wlan_event is not None:
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}: {wlan_event}")
        if wlan_event.data:
            print(f"  Data: {wlan_event.data}")


async def main():
    ifaces = getWirelessInterfaces()
    print(f"Found {len(ifaces)} interface(s).")
    for iface in ifaces:
        print(f"  - {iface.guid} ({iface.description})")

    print("Registering for notifications...")
    # Keep a reference to the notification object to prevent it from being garbage collected
    notification_obj = registerNotification(demo)
    print("Successfully registered. Press Ctrl+C to stop.")

    try:
        # Keep the script running
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping...")
