# Python Packet Capture Program

This folder contains `packet_capture.py`, a small command-line packet capture tool.

It can:

- capture live packets,
- print TCP, UDP, ICMP, ARP, IPv4, and IPv6 summaries,
- save captured packets to a `.pcap` file,
- use Scapy/Npcap when installed,
- fall back to raw sockets on Linux and Windows.

## Requirements

Python 3.9 or newer is recommended.

For best results install Scapy:

```powershell
python -m pip install scapy
```

On Windows, install Npcap too:

```text
https://npcap.com/#download
```

Packet capture usually requires Administrator/root privileges.

## Examples

Capture 20 packets:

```powershell
python .\packet_capture.py --count 20
```

Capture for 30 seconds and save to a pcap:

```powershell
python .\packet_capture.py --duration 30 --output capture.pcap
```

Use a specific interface:

```powershell
python .\packet_capture.py --interface "Wi-Fi" --count 50
```

Use a capture filter with Scapy:

```powershell
python .\packet_capture.py --backend scapy --filter "tcp port 443" --count 25
```

List interfaces:

```powershell
python .\packet_capture.py --list-interfaces
```

On Windows raw-socket fallback, bind to a local host IP:

```powershell
python .\packet_capture.py --backend raw --host 192.168.1.25 --count 20
```

## Backend Notes

`--backend auto` tries Scapy first, then falls back to raw sockets.

`--backend scapy` gives the most complete capture support, including BPF filters and interface selection.

`--backend raw` avoids third-party packages, but has limits:

- Linux raw sockets capture Ethernet frames from `AF_PACKET`.
- Windows raw sockets capture raw IP packets only.
- macOS should use Scapy/libpcap.

## Output

Each packet is printed like this:

```text
14:23:41.102     74 bytes  Ethernet/IPv4/TCP  192.168.1.20:51544 -> 142.250.72.14:443 flags=ACK payload=0
```

If `--output capture.pcap` is set, the packets are also written to a file that can be opened in Wireshark.

## Dashboard

Generate dashboard data from a pcap:

```powershell
python .\generate_dashboard.py .\live_capture_admin.pcap -o .\dashboard_data.js
```

Open the dashboard:

```powershell
python -m http.server 8765 --directory .
```

Then visit:

```text
http://127.0.0.1:8765/network_dashboard.html
```

The dashboard includes KPIs, a traffic timeline, protocol mix, top conversations, top endpoints, findings, a searchable packet table, JSON export, and browser-side `.pcap` loading.
