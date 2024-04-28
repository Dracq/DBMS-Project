from scapy.all import sniff, ARP, Ether

# Predefined IP-MAC binding map
ip_mac_binding_map = {
    "192.168.1.1": "00:11:22:33:44:55",
    "192.168.1.2": "aa:bb:cc:dd:ee:ff",
    # Add more IP-MAC mappings as needed
}

def process_arp_packet(packet):
    if ARP in packet:
        arp_layer = packet[ARP]
        if arp_layer.op == 1:  # ARP Request
            ip_address = arp_layer.pdst
            mac_address = arp_layer.hwsrc
            if ip_address in ip_mac_binding_map:
                expected_mac = ip_mac_binding_map[ip_address]
                if mac_address != expected_mac:
                    print(f"WARNING: ARP Spoofing detected! IP: {ip_address}, Expected MAC: {expected_mac}, Actual MAC: {mac_address}")
        elif arp_layer.op == 2:  # ARP Reply
            ip_address = arp_layer.psrc
            mac_address = arp_layer.hwsrc
            if ip_address in ip_mac_binding_map:
                expected_mac = ip_mac_binding_map[ip_address]
                if mac_address != expected_mac:
                    print(f"ALERT: ARP cache poisoning! IP: {ip_address}, Expected MAC: {expected_mac}, Actual MAC: {mac_address}")

def start_sniffing():
    # Start sniffing for ARP packets
    sniff(filter="arp", prn=process_arp_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
 