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

import threading
from datetime import datetime
from win32wifi.Win32Wifi import (
    getWirelessInterfaces,
    registerNotification,
    unregisterNotification
)

stop_event = threading.Event()


def notification_callback(wlan_event, context):
    if wlan_event is not None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(f"[{timestamp}] {wlan_event.notificationSource}: {wlan_event.notificationCode}")
        if wlan_event.data:
            print(f"Data: {wlan_event.data}")
        stop_event.set()


def main():
    ifaces = getWirelessInterfaces()
    for iface in ifaces:
        print(f"Interface: {iface.description} ({iface.guid})")

    print("Registering for notifications...")
    notification_object = registerNotification(notification_callback)
    print("Registered. Waiting for an event (e.g., toggle WiFi)...")

    try:
        # Wait up to 30 seconds for an event
        if stop_event.wait(timeout=30):
            print("Received a notification.")
        else:
            print("Timed out waiting for a notification.")
    finally:
        print("Unregistering notifications...")
        unregisterNotification(notification_object)
        print("Done.")


if __name__ == "__main__":
    main()
