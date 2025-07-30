from scapy.all import *
#A function that returns info about each packet
def pkt_info(pkt):
    #Initialize a dictionary to hold packet information
    info = {
        "direction": None,
        "src_mac": pkt.src, #Source MAC address
        "dst_mac": pkt.dst, #Destination MAC address
        "src_ip": None, 
        "dst_ip": None, 
        "ip_layer": None, #IP layer type (IPv4 or IPv6)
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "length": None,
        "payload": None,
        "flags": None
    }
    # Get local IP address
    local_ip= get_if_addr(conf.iface)
    # Determine IP version
    if pkt.haslayer(IP):
        info["ip_layer"] = IP
    elif pkt.haslayer(IPv6):
        info["ip_layer"] = IPv6
    else:
        return None
    #Direction of the packet
    info["direction"]= "IN" if local_ip == pkt[info["ip_layer"]].dst else "OUT"
    # Extract IP layer information
    info["src_ip"] = pkt[info["ip_layer"]].src
    info["dst_ip"] = pkt[info["ip_layer"]].dst
    info["length"] = pkt[info["ip_layer"]].len
    # Process transport layer
    if pkt.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport #N.B: UDP does not have flags like TCP
    elif pkt.haslayer(ICMP):
        info["protocol"] = "ICMP"
        info["flags"] = str(pkt[ICMP].flags)

    # Extract payload from Raw layer if present
    if pkt.haslayer(Raw):
        try:
            payload = hexdump(pkt[Raw].load, dump=True)
            info["payload"] = "\n" + payload
        except Exception:
            pass  # Keep payload as None if extraction fails

    return info

def display_pkt(pkt):
    info = pkt_info(pkt)
    src_port = info["src_port"]
    dst_port = info["dst_port"]
    port_str = f"{src_port}:{dst_port}" # Format ports

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

def displayer(interface=None, pkt_count=10):
    print(f"[*] Starting sniffer on {interface or 'all interfaces'} for {pkt_count} pkts")
    wrpcap("packets.pcap",sniff(iface=interface, prn=display_pkt, count=pkt_count))
    print("[*] Sniffing complete")

if __name__ == "__main__":
    displayer()