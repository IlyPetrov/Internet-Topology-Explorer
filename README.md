# Multi-Protocol Traceroute Tool

This project implements a multi-protocol traceroute tool in Python, which sends ICMP, UDP, or TCP packets to trace the route of remote hosts. The tool measures per-hop latency, builds a topology graph, and displays static graphs, interactive network diagrams, and IP geolocation maps.

---

## Table of Contents
- [Features](#features)
- [Usage](#usage)
- [Command Line Arguments](#command-line-arguments)
- [Code Structure](#code-structure)
- [Visualization Outputs](#visualization-outputs)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)

---

## Features

- Utilizes ICMP, UDP, TCP protocols to create traceroutes
- Visualizes traceroute output as:
  - Static graphs using Matplotlib
  - Interactive HTML graphs using PyVis
  - Geolocation-based maps using Folium
- Optional DNS resolution for IP addresses
- User-configurable TTL ranges, port numbers, timeout settings, payload size, and delay
- Handles both public and private IPs

---


## Usage

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

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `txtfile` | Path to input file containing target hosts (required) |
| `-n` | Turn off DNS resolution of IP addresses |
| `-w` | Timeout (1–300s) to wait for ICMP response (default: 5) |
| `-m` | Initial TTL (1–255) value (default: 1) |
| `-M` | Max TTL (1–255) to probe (default: 30) |
| `-p` | Starting UDP destination port (1–65535) (default: 33434) |
| `-q` | Probes per hop (1–255) (default: 1) |
| `-uti` | Protocol to use: `icmp`, `udp`, `tcp`, or `all` (default: all) |
| `-datasize` | Optional payload size (0–1420) in bytes (default: 0) |
| `-z`, `--inter_packet_delay` | Delay between packets in seconds (default: 0) |

---

## Code Structure

### `main()`
- Parses command-line arguments using `argparse`
- Reads target hostnames from file
- Calls `multi_protocol_traceroute()` for every target hostname

### `multi_protocol_traceroute(target, args)`
- Iterates through three protocols to use (ICMP, UDP, TCP)
- Calls `traceroute_probe()`
- Collects hop results and calls visualization functions

### `traceroute_probe(...)`
- Constructs IP packets with successive TTL values
- Uses Scapy to send packets and record round-trip latency
- Tracks responses and builds a NetworkX graph of the route

### `plot_graph(...)`
- Builds graphs using NetworkX and Matplotlib
- Saves protocol-specific PNG plots and combined latency bar charts to computer

### `plot_interactive_graph(...)`
- Builds HTML graphs using PyVis
- Labels nodes and edges with latency information
- Saves and opens HTML files in browser

### `geolocate_ip(ip)`
-  ipinfo.io provides IP geolocation information

### `plot_geolocation_map(...)`
- Uses Folium to build a geographic route map
- Adds markers and lines based on hop locations
- Saves and opens HTML files in browser

### `get_domain_name(ip)`
- Performs reverse DNS lookup if enabled

---

## Visualization Outputs

For each target and protocol, the tool produces:

- **Static Graph**: `{target}_{proto}_graph.png`
- **Combined Bar Chart**: `{target}_combined_latency.png`
- **Interactive HTML Graph**: `{target}_{proto}_interactive.html`
- **Geo Map**: `{target}_{proto}_geopath.html`

These files visualize the route taken by packets to reach the target, per-protocol latency comparisons, and the physical/geographical distribution of hops.

---

## Limitations

- Private IPs cannot be geolocated and are not visualized on map
- Geolocation is limited by ipinfo.io rate limits unless an API key is used
- Some firewalls or ISPs may block traceroute packets

---

## Future Enhancements

- GUI
