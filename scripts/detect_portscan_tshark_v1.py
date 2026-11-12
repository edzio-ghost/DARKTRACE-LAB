
import subprocess
from collections import defaultdict, deque
from datetime import datetime

# ==========================================
# CONFIGURATION
# ==========================================

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
PCAP_PATH = r"data\pcap\Friday-WorkingHours.pcap"

WINDOW_SECONDS = 60
PORT_THRESHOLD = 20

# Première expérience : analyser 50 000 SYN
MAX_SYN_PACKETS = 50000

# ==========================================
# STRUCTURES
# ==========================================

connections = defaultdict(deque)
max_ports_seen = defaultdict(int)
alerted = set()

syn_count = 0
alert_count = 0
first_timestamp = None
last_timestamp = None

# ==========================================
# LANCEMENT TSHARK
# ==========================================

command = [
    TSHARK_PATH,
    "-r", PCAP_PATH,
    "-Y", "ip && tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.dstport"
]

print("--- DARKTRACE LAB : PORTSCAN DETECTOR ---")
print("Fenêtre temporelle :", WINDOW_SECONDS, "secondes")
print("Seuil de ports :", PORT_THRESHOLD)
print("Limite de SYN :", MAX_SYN_PACKETS)
process = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

try:
    for line in process.stdout:

        fields = line.strip().split("\t")

        if len(fields) != 4:
            continue

        try:
            timestamp = float(fields[0])
            src = fields[1]
            dst = fields[2]
            port = int(fields[3])
        except ValueError:
            continue

        syn_count += 1

        if first_timestamp is None:
            first_timestamp = timestamp

        last_timestamp = timestamp

        key = (src, dst)
        history = connections[key]

        # Ajouter la tentative SYN
        history.append((timestamp, port))

        # Fenêtre glissante de 10 secondes
        while history and timestamp - history[0][0] > WINDOW_SECONDS:
            history.popleft()

        # Ports distincts
        unique_ports = {p for _, p in history}

        max_ports_seen[key] = max(
            max_ports_seen[key],
            len(unique_ports)
        )

        # Détection
        if len(unique_ports) >= PORT_THRESHOLD:

            if key not in alerted:
                alerted.add(key)
                alert_count += 1

                print("\n[ALERTE PORTSCAN POTENTIEL]")

                print(
                    "Date :",
                    datetime.fromtimestamp(timestamp)
                )
                print("Source :", src)
                print("Destination :", dst)
                print("Ports distincts :", len(unique_ports))

        if syn_count >= MAX_SYN_PACKETS:
            break

finally:
    # Arrêter TShark proprement
    if process.poll() is None:
        process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

    if process.stdout:
        process.stdout.close()

    if process.stderr:
        process.stderr.close()

# ==========================================
# RÉSULTATS
# ==========================================

print("\n--- RÉSULTATS ---")
print("Tentatives SYN analysées :", syn_count)
print("Alertes :", alert_count)

print("\n--- TOP 10 ACTIVITÉS ---")

top = sorted(
    max_ports_seen.items(),
    key=lambda item: item[1],
    reverse=True
)[:10]

for (src, dst), count in top:
    print(
        f"{src} -> {dst} | "
        f"Maximum de ports en {WINDOW_SECONDS}s : {count}"
    )

print("\n--- PÉRIODE ANALYSÉE ---")

if first_timestamp is not None:
    print("Début :", datetime.fromtimestamp(first_timestamp))
    print("Fin :", datetime.fromtimestamp(last_timestamp))
    print(
        "Durée (minutes) :",
        round((last_timestamp - first_timestamp) / 60, 2)
    )
