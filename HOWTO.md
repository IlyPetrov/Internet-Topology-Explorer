# How to Install and Run the Multi-Protocol Traceroute Tool

This guide explains how to install libraries, prepare inputs, and run the traceroute tool from the command line.

---

## Requirements
- Python 3.7 or newer
- Internet connection (for IP geolocation and DNS resolution)

---

## Step 1: Install Python Libraries
Use pip to install all required Python libraries:

```bash
pip install scapy matplotlib networkx pyvis folium requests
```
---

## Step 2: Prepare a Target Input File
Create a `.txt` file with one IP address or domain name per line.

Example:
```text
targets.txt
```
```
8.8.8.8
google.com
```

---

## Step 3: Run the Program
Use the command below to launch the traceroute tool:

```bash
python trace_4.py targets.txt
```

### Optional Flags:
You can choose the behavior using options such as:

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

## Step 4: View the Output Files
The script will generate the following for each target:

- `target_protocol_graph.png` — Static path graph
- `target_combined_latency.png` — Bar chart of all protocols
- `target_protocol_interactive.html` — Clickable interactive graph
- `target_protocol_geopath.html` — Geolocation map with hops

Open the `.html` files in any browser to view the interactive visualizations.