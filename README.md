# win32wifi (Python Windows Wifi)

win32wifi is a set of Python bindings for the Windows Native Wifi API, modernized for Python 3.8+.

The Native Wifi API is designed for developers working with wireless networking on Windows. Programmers should be familiar with wireless networking concepts and terminology.

## Requirements

- Windows Operating System
- Python 3.8 or later
- `comtypes`
- `xmltodict`

## Installation

You can install the library directly from the source:

```bash
pip install .
```

## Features

- Enumerate wireless interfaces
- Scan for available networks
- Retrieve BSS lists (with Information Elements)
- Manage wireless profiles (get, set, delete)
- Connect to and disconnect from networks
- Monitor WiFi notifications
- Query interface capabilities

## Usage Example

```python
from win32wifi import Win32Wifi

# List interfaces
interfaces = Win32Wifi.getWirelessInterfaces()
for iface in interfaces:
    print(f"Interface: {iface.description} ({iface.state_string})")

    # List available networks
    networks = Win32Wifi.getWirelessAvailableNetworkList(iface)
    for network in networks:
        print(f"  SSID: {network.ssid.decode('utf-8', 'replace')}, Signal: {network.signal_quality}%")
```

## Authors

- Andres Blanco (6e726d) — original PyWiWi author
- [kedos](https://github.com/kedos) — current maintainer

## License

GNU General Public License v3 or later (GPLv3+). See `LICENSE` for details.

## References

- [Windows Native Wifi API](https://learn.microsoft.com/en-us/windows/win32/nativewifi/portal)
