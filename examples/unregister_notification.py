import threading
from win32wifi.Win32Wifi import *

event = threading.Event()


def demo(wlan_event):
    if wlan_event is not None:
        print("%s: %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), wlan_event))
        event.set()


def main():
    ifaces = getWirelessInterfaces()
    for iface in ifaces:
        print(iface.guid)

    print("Registering...")
    notification_object = registerNotification(demo)
    print("Done.")

    event.wait()

    print("Unregistered Notification...")
    unregisterNotification(notification_object)
    print("Done.")


if __name__ == "__main__":
    main()

    import time

    while True:
        time.sleep(0)
