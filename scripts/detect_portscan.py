
from scapy.all import PcapReader, IP, TCP
from collections import defaultdict, deque
from datetime import datetime

# ==========================================
# CONFIGURATION
# ==========================================

pcap_path = "data/pcap/Friday-WorkingHours.pcap"

WINDOW_SECONDS = 10
PORT_THRESHOLD = 20

# Limite pour notre première expérience
MAX_PACKETS = 2000000

# ==========================================
# STRUCTURES DE DONNÉES
# ==========================================

# Pour chaque paire source/destination :
# conserver les tentatives SYN récentes
connections = defaultdict(deque)

# Éviter de répéter la même alerte
alerted = set()

# Conserver le maximum de ports distincts
# observés dans une fenêtre de 10 secondes
max_ports_seen = defaultdict(int)

packet_count = 0
syn_count = 0
alert_count = 0
first_timestamp = None
last_timestamp = None

print("--- DÉTECTION COMPORTEMENTALE PORTSCAN ---")

# ==========================================
# LECTURE PROGRESSIVE DU PCAP
# ==========================================

with PcapReader(pcap_path) as pcap:

    for packet in pcap:

        if packet_count >= MAX_PACKETS:
            break

        packet_count += 1
        # Suivre la période couverte par les paquets
        packet_timestamp = float(packet.time)
        if first_timestamp is None:
            first_timestamp = packet_timestamp
        last_timestamp = packet_timestamp

        if IP not in packet or TCP not in packet:
            continue

        tcp = packet[TCP]

        # SYN activé et ACK désactivé :
        # tentative initiale de connexion TCP
        if not (tcp.flags & 0x02):
            continue

        if tcp.flags & 0x10:
            continue

        syn_count += 1

        timestamp = float(packet.time)

        src = packet[IP].src
        dst = packet[IP].dst
        port = int(tcp.dport)

        key = (src, dst)

        history = connections[key]

        # Ajouter la tentative de connexion
        history.append((timestamp, port))

        # Supprimer les tentatives trop anciennes
        while history and timestamp - history[0][0] > WINDOW_SECONDS:
            history.popleft()

        # Compter les ports distincts
        unique_ports = {p for _, p in history}

        # Conserver le maximum de ports distincts
        # observés dans une fenêtre de 10 secondes
        max_ports_seen[key] = max(
            max_ports_seen[key],
            len(unique_ports)
        )

        if len(unique_ports) >= PORT_THRESHOLD:

            # Une seule alerte par paire IP
            if key not in alerted:

                alerted.add(key)
                alert_count += 1

                time_text = datetime.fromtimestamp(
                    timestamp
                ).isoformat()

                print("\n[ALERTE PORTSCAN POTENTIEL]")

                print("Date :", time_text)
                print("Source :", src)
                print("Destination :", dst)
                print("Ports distincts :", len(unique_ports))
                print("Fenêtre :", WINDOW_SECONDS, "secondes")

# ==========================================
# RÉSULTATS
# ==========================================

print("\n--- RÉSULTATS ---")

print("Paquets parcourus :", packet_count)
print("Tentatives SYN :", syn_count)
print("Alertes générées :", alert_count)

# ==========================================
# STATISTIQUES DES SOURCES
# ==========================================

print("\n--- TOP 10 ACTIVITÉS SUSPECTES ---")

top_sources = sorted(
    max_ports_seen.items(),
    key=lambda item: item[1],
    reverse=True
)[:10]

for (src, dst), count in top_sources:
    print(
        f"Source : {src} | "
        f"Destination : {dst} | "
        f"Maximum de ports en 10s : {count}"
    )

print("\nNombre de paires IP analysées :", len(max_ports_seen))


# ==========================================
# PÉRIODE ANALYSÉE
# ==========================================

print("\n--- PÉRIODE ANALYSÉE ---")

if first_timestamp is not None:
    start = datetime.fromtimestamp(first_timestamp)
    end = datetime.fromtimestamp(last_timestamp)

    duration = last_timestamp - first_timestamp

    print("Début :", start)
    print("Fin :", end)
    print("Durée en secondes :", round(duration, 2))
    print("Durée en minutes :", round(duration / 60, 2))