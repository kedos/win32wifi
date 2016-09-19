import asyncio

from win32wifi.Win32Wifi import *


def demo(wlan_event):
    if wlan_event != None:
        print("%s: %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), wlan_event))

@asyncio.coroutine
def main():
    ifaces = getWirelessInterfaces()
    for iface in ifaces:
        print(iface.guid)

    print("Registering...")
    registerNotification(demo)
    print("Done.")

    yield from asyncio.Event().wait()


if __name__ == "__main__":
    loop = asyncio.ProactorEventLoop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
    loop.close()
