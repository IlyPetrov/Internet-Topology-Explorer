import argparse
import socket
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import networkx as nx
from scapy.all import IP, ICMP, UDP, TCP, sr1, RandShort, Raw
from concurrent.futures import ThreadPoolExecutor
import os
import threading
from pyvis.network import Network
import webbrowser
import math
import requests
import folium

# Helper function
def get_domain_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip
    
def geolocate_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        if "loc" in data:
            lat, lon = map(float, data["loc"].split(","))
            return lat, lon, data.get("city", ""), data.get("org", "")
    except Exception as e:
        print(f"Geo error for {ip}: {e}")
    return None, None, "", ""

def log_raw_result(protocol, ttl, ip, domain, latency, target):
    with open(f"{target}_raw_results.txt", "a") as log_file:
        if ip:
            log_file.write(f"{protocol} - TTL {ttl}: {domain} ({ip}) - {latency*1000:.2f} ms\n")
        else:
            log_file.write(f"{protocol} - TTL {ttl}: * * * Request timed out\\n")

def traceroute_probe(destination, protocol, max_hops, results, lock, resolve_dns=True, timeout=1,
                     start_ttl=1, dport_base=33434, probes_per_hop=1, datasize=0, inter_packet_delay=0):
    ttl = start_ttl
    prev_ip = None
    G = nx.Graph()
    edge_latencies = {}
    while ttl <= max_hops:
        reached = False
        for _ in range(probes_per_hop):
            ip_packet = IP(dst=destination, ttl=ttl)
            payload = Raw(load='X' * max(datasize - 20, 0)) if datasize > 20 else Raw(load='')

            if protocol == 'ICMP':
                packet = ip_packet / ICMP() / payload
            elif protocol == 'UDP':
                packet = ip_packet / UDP(sport=RandShort(), dport=dport_base + ttl - 1) / payload
            elif protocol == 'TCP':
                packet = ip_packet / TCP(sport=RandShort(), dport=80, flags="S") / payload
            else:
                return G, edge_latencies

            send_time = time.time()
            reply = sr1(packet, verbose=False, timeout=timeout)
            latency = time.time() - send_time
            
            with lock:

                if reply is not None:
                    src_ip = reply.src
                    domain = src_ip if not resolve_dns else get_domain_name(src_ip)
                    results[protocol][ttl] = {"ip": src_ip, "name": domain, "latency": latency}
                    log_raw_result(protocol, ttl, src_ip, domain, latency, destination)
                    G.add_node(src_ip, name=domain)
                    if prev_ip:
                        G.add_edge(prev_ip, src_ip, weight=latency)
                        edge_latencies[(prev_ip, src_ip)] = latency
                    prev_ip = src_ip
                    print(f"{protocol:<5}- {ttl}. {domain} ({src_ip}) {latency*1000:.2f}ms")
                    if reply.src == socket.gethostbyname(destination) or (hasattr(reply, 'type') and reply.type == 3):
                        reached = True
                        return G, edge_latencies, reached
                else:
                    results[protocol][ttl] = {"ip": None, "name": None, "latency": None}
                    log_raw_result(protocol, ttl, None, None, None, destination)
            time.sleep(inter_packet_delay)
        ttl += 1
    return G, edge_latencies, reached

def multi_protocol_traceroute(target, args):
    protocols = ['UDP', 'TCP', 'ICMP'] if args.uti == 'all' else [args.uti.upper()]
    results = defaultdict(lambda: defaultdict(dict))
    lock = threading.Lock()
    for proto in protocols:
        print(f"Tracing {target} using {proto}...")
        g, latencies, reached = traceroute_probe(
            target, proto, args.M, results, lock,
            resolve_dns=not args.n,
            timeout=args.w,
            start_ttl=args.m,
            dport_base=args.p,
            probes_per_hop=args.q,
            datasize=args.datasize,
            inter_packet_delay=args.inter_packet_delay
        )
        if reached == True:
            print("Destionation Reached")
        plot_interactive_graph(g, target, proto)
        plot_geolocation_map(results, target, proto)
    plot_graph(target, results)

    
def plot_graph(target, results):
    protocols = ['UDP', 'TCP', 'ICMP']
    for proto in protocols:
        ttl_vals = sorted(results[proto].keys())
        ips = [results[proto][ttl]['ip'] if results[proto][ttl]['ip'] else "*" for ttl in ttl_vals]
        latencies = [results[proto][ttl]['latency'] if results[proto][ttl]['latency'] is not None else 0 for ttl in ttl_vals]

        # Create a graph for each protocol
        G = nx.DiGraph()
        prev_ip = None
        for idx, ttl in enumerate(ttl_vals):
            ip = ips[idx]
            latency = latencies[idx]
            if prev_ip and ip != "*":
                # Add edge with latency as weight (or label)
                G.add_edge(prev_ip, ip, weight=latency)
            G.add_node(ip)

            prev_ip = ip

        # Plot the graph with IP nodes and latency edges
        plt.figure(figsize=(10, 6))
        pos = nx.spring_layout(G)  # Layout of the graph
        nx.draw(G, pos, with_labels=True, node_size=2000, node_color='lightblue', font_size=10, font_weight='bold')
        
        # Add latency labels on edges
        edge_labels = nx.get_edge_attributes(G, 'weight')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

        # Title and labels for the plot
        plt.title(f"{proto} Path to {target}")
        plt.xlabel("Node (IP)")
        plt.ylabel("Latency (s)")
        plt.xticks(rotation=90)
        plt.tight_layout()

        # Save the graph as a PNG file
        plt.savefig(f"{target}_{proto}_graph.png")
        plt.close()

    # Combined graph
    ttl_vals = sorted(set.union(*(set(results[proto].keys()) for proto in protocols)))
    width = 0.2
    plt.figure(figsize=(12, 6))
    for idx, proto in enumerate(protocols):
        latencies = [results[proto][ttl]['latency'] if ttl in results[proto] and results[proto][ttl]['latency'] is not None else 0 for ttl in ttl_vals]
        plt.bar([x + idx * width for x in range(len(ttl_vals))], latencies, width=width, label=proto)

    plt.title(f"Combined Latency to {target}")
    plt.xlabel("Hop")
    plt.ylabel("Latency (s)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{target}_combined_latency.png")
    plt.close()

def plot_interactive_graph(G, target, proto):
    net = Network(notebook=False, height="750px", width="100%", bgcolor="#222222", font_color="white")
    for node in G.nodes:
        label = G.nodes[node].get("name", node)
        net.add_node(node, label=label, font={"size": 20})
    for src, dst in G.edges:
        latency = G.edges[src, dst].get("weight", 0)
        net.add_edge(
            src,
            dst,
            title=f"{latency*1000:.2f} ms",
            label=f"{latency*1000:.2f} ms",
            #value=max(latency * 1000, 1)  # use ms, minimum value to keep edge visible
            # value = math.log(latency * 1000 + 1),
            font = {"size": 15},
            length=latency * 7500
        )
    filename = f"{target}_{proto}_interactive.html"
    net.save_graph(filename)
    webbrowser.open(filename)
    print(f"Interactive graph saved as {filename}")
    
def plot_geolocation_map(results, target, proto):
    ttl_keys = sorted(results[proto].keys())
    locations = []

    for ttl in ttl_keys:
        hop = results[proto][ttl]
        ip = hop.get("ip")
        if ip:
            lat, lon, city, org = geolocate_ip(ip)
            if lat and lon:
                label = f"{ip}\n{city}\n{org}\n{hop['latency']*1000:.2f} ms"
                locations.append((lat, lon, label))
    if not locations:
        print("No geolocation data found.")
        return

    # Center map on first location
    start_coords = locations[0][:2]
    m = folium.Map(location=start_coords, zoom_start=3, tiles="CartoDB positron")

    # Add markers and lines
    for i, (lat, lon, label) in enumerate(locations):
        folium.Marker(location=[lat, lon], popup=label, tooltip=f"Hop {i+1}").add_to(m)
        if i > 0:
            prev = locations[i - 1]
            folium.PolyLine(locations=[(prev[0], prev[1]), (lat, lon)], color="blue").add_to(m)

    map_filename = f"{target}_{proto}_geopath.html"
    m.save(map_filename)
    print(f"Geolocation map saved as {map_filename}")
    webbrowser.open(map_filename)


def main():
    parser = argparse.ArgumentParser(description="Multi-protocol Traceroute Tool")
    parser.add_argument("txtfile", help='path to text file with hostnames or IPs', type=str)
    parser.add_argument("-n", help="Do not resolve addresses to hostnames", action="store_true")
    parser.add_argument("-w", help="Wait time for ICMP response (1–300s)", type=int, default=5)
    parser.add_argument("-m", help="Initial TTL (1–255)", type=int, default=1)
    parser.add_argument("-M", help="Max TTL (1–255)", type=int, default=30)
    parser.add_argument("-p", help="UDP destination port (1–65535)", type=int, default=33434)
    parser.add_argument("-q", help="Number of series per hop (1–255)", type=int, default=1)
    parser.add_argument("-uti", help="Protocol: icmp, udp, tcp, or all", type=str, default="all")
    parser.add_argument("-datasize", help="Payload size (0–1420)", nargs="?", type=int, default=0)
    parser.add_argument("-z", "--inter_packet_delay", help="Waiting time (seconds) between consecutive packets", type=float, default=0)

    args = parser.parse_args()

    if not os.path.exists(args.txtfile):
        print("File not found.")
        return

    with open(args.txtfile) as f:
        targets = [line.strip() for line in f if line.strip()]

    for target in targets:
        try:
            multi_protocol_traceroute(target, args)
        except Exception as e:
            print(f"Error tracing {target}: {e}")


if __name__ == "__main__":
    main()
