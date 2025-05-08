# 🛰️ Multi-Protocol Traceroute Tool

This project implements a multi-protocol traceroute tool in Python, capable of sending ICMP, UDP, or TCP packets to trace the route to one or more remote hosts. The tool measures per-hop latency, builds a topology graph, and provides multiple forms of visualization including static graphs, interactive network diagrams, and IP geolocation maps.

---

## 📋 Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command Line Arguments](#command-line-arguments)
- [Code Structure](#code-structure)
- [Visualization Outputs](#visualization-outputs)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)

---

## 🚀 Features

- Supports ICMP, UDP, TCP protocols for flexible traceroute probing
- Visualizes traceroute output as:
  - Static graphs using Matplotlib
  - Interactive HTML graphs using PyVis
  - Geolocation-based maps using Folium
- Optional DNS resolution for IP addresses
- User-configurable TTL ranges, port numbers, timeout settings, payload size, and delay
- Handles both public and private IPs

---

## 🔧 Installation

Ensure Python 3.7+ is installed. Install dependencies via pip:

```bash
pip install scapy matplotlib networkx pyvis folium requests
```

---

## 🖥️ Usage

Create a text file with one hostname or IP per line:

**Example: targets.txt**
```
8.8.8.8
google.com
```

Run the traceroute tool with:

```bash
python trace_4.py targets.txt -uti all -q 3 -M 20
```

---

## 🧾 Command Line Arguments

| Argument | Description |
|----------|-------------|
| `txtfile` | Path to input file containing target hosts (required) |
| `-n` | Disable DNS resolution of IPs |
| `-w` | Timeout (seconds) to wait for response (default: 5) |
| `-m` | Initial TTL value (default: 1) |
| `-M` | Max TTL to probe (default: 30) |
| `-p` | Starting UDP destination port (default: 33434) |
| `-q` | Probes per hop (default: 1) |
| `-uti` | Protocol to use: `icmp`, `udp`, `tcp`, or `all` (default: all) |
| `-datasize` | Optional payload size in bytes (default: 0) |
| `-z`, `--inter_packet_delay` | Delay between packets in seconds (default: 0) |

---

## 🧠 Code Structure

### `main()`
- Parses command-line arguments using `argparse`
- Reads target hostnames from file
- Calls `multi_protocol_traceroute()` for each target

### `multi_protocol_traceroute(target, args)`
- Determines which protocol(s) to use (ICMP, UDP, TCP)
- Calls `traceroute_probe()`
- Collects hop results and calls visualization functions

### `traceroute_probe(...)`
- Constructs IP packets with incrementing TTL values
- Uses Scapy to send packets and measure round-trip latency
- Tracks responses and builds a NetworkX graph of the route

### `plot_graph(...)`
- Builds static graphs using NetworkX and Matplotlib
- Saves protocol-specific PNG plots and combined latency bar charts

### `plot_interactive_graph(...)`
- Builds interactive HTML graphs using PyVis
- Labels nodes and edges with latency information
- Saves and opens HTML files in browser

### `geolocate_ip(ip)`
- Queries ipinfo.io for IP geolocation data

### `plot_geolocation_map(...)`
- Uses Folium to build a geographic route map
- Adds markers and lines based on hop locations
- Saves interactive HTML map to disk

### `get_domain_name(ip)`
- Performs reverse DNS lookup if enabled

---

## 📊 Visualization Outputs

For each target and protocol, the tool produces:

- **Static Graph**: `{target}_{proto}_graph.png`
- **Combined Bar Chart**: `{target}_combined_latency.png`
- **Interactive HTML Graph**: `{target}_{proto}_interactive.html`
- **Geo Map**: `{target}_{proto}_geopath.html`

These files visualize the route taken by packets to reach the target, per-protocol latency comparisons, and the physical/geographical distribution of hops.

---

## ⚠️ Limitations

- Private IPs cannot be geolocated
- Requires root/admin privileges to send raw packets
- Geolocation is limited by ipinfo.io rate limits unless an API key is used
- Some firewalls or ISPs may block traceroute packets

---

## 💡 Future Enhancements

- Add progress bars (`tqdm`) and colored terminal output
- Support traceroute over IPv6
- Retry logic for inconsistent responses
- GUI or web frontend using Streamlit
- Use of personal API keys for higher geolocation resolution
