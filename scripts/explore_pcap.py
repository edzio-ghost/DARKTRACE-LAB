
from scapy.all import PcapReader, IP, TCP, UDP

# ==========================================
# CONFIGURATION
# ==========================================

pcap_path = "data/pcap/Friday-WorkingHours.pcap"

max_packets = 20

# ==========================================
# LECTURE PROGRESSIVE DU PCAP
# ==========================================

print("--- EXPLORATION DU PCAP ---")

packet_count = 0

with PcapReader(pcap_path) as pcap:

    for packet in pcap:

        if IP not in packet:
            continue

        packet_count += 1

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        timestamp = float(packet.time)

        protocol = "OTHER"
        source_port = "-"
        destination_port = "-"

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        print(f"\n--- PAQUET {packet_count} ---")
        print("Source IP :", source_ip)
        print("Destination IP :", destination_ip)
        print("Timestamp :", timestamp)
        print("Protocole :", protocol)
        print("Source Port :", source_port)
        print("Destination Port :", destination_port)

        if packet_count >= max_packets:
            break

print("\nPaquets IPv4 analysés :", packet_count)
