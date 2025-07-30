from scapy.all import *

def pkt_info(packet):
    info = {
        "direction": None,
        "src_mac": packet.src,
        "dst_mac": packet.dst,
        "src_ip": None,
        "dst_ip": None,
        "ip_layer": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "length": None,
        "payload": None,
        "flags": None
    }
    # Get local IP address
    local_ip= get_if_addr(conf.iface)
    # Determine IP version and layer
    if packet.haslayer(IP):
        info["ip_layer"] = IP
    elif packet.haslayer(IPv6):
        info["ip_layer"] = IPv6
    else:
        return info  # Return available info (MAC addresses)
    #Direction of the packet
    info["direction"]= "IN" if local_ip == packet[info["ip_layer"]].dst else "OUT"
    # Extract IP layer information
    info["src_ip"] = packet[info["ip_layer"]].src
    info["dst_ip"] = packet[info["ip_layer"]].dst
    info["length"] = packet[info["ip_layer"]].len

    # Process transport layer
    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"
        info["flags"] = str(packet[ICMP].flags)

    # Extract payload from Raw layer if present
    if packet.haslayer(Raw):
        try:
            payload = hexdump(packet[Raw].load, dump=True)
            info["payload"] = "\n" + payload
        except Exception:
            pass  # Keep payload as None if extraction fails

    return info

def display_pkt(packet):
    info = pkt_info(packet)
    # Format ports if available
    src_port = info["src_port"]
    dst_port = info["dst_port"]
    port_str = f"{src_port}:{dst_port}"

    print(
        f"[{info['direction']}] "
        f"MAC: {info['src_mac']} -> {info['dst_mac']} | "
        f"IP: {info['src_ip']} -> {info['dst_ip']} | "
        f"Proto: {info['protocol'] or 'Unknown'} {port_str} | "
        f"Length: {info['length']} | "
        f"Flags: {info['flags'] or ''}"
    )
    if info["payload"]:
        print(f"Payload: {info['payload']}")

def displayer(interface=None, packet_count=10):
    print(f"[*] Starting sniffer on {interface or 'all interfaces'} for {packet_count} packets")
    sniff(iface=interface, prn=display_pkt, count=packet_count)
    print("[*] Sniffing complete")

if __name__ == "__main__":
    displayer(packet_count=50)