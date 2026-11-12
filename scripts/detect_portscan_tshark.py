# -*- coding: utf-8 -*-
import json
from pathlib import Path
import subprocess
import re

ftp_passive_ports = {}
ftp_explained_count = 0
from collections import defaultdict, deque
from datetime import datetime, timezone

# ==========================================
# CONFIGURATION
# ==========================================

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
PCAP_PATH = str(Path(__file__).resolve().parents[1] / "data" / "pcap" / "Friday-WorkingHours.pcap")

WINDOW_SECONDS = 60
PORT_THRESHOLD = 20

# None analyse le PCAP complet.
MAX_SYN_PACKETS = None

# ==========================================
# STRUCTURES
# ==========================================

connections = defaultdict(deque)
max_ports_seen = defaultdict(int)
alerted = set()

syn_count = 0
alert_count = 0
alerts = []
OUTPUT_PATH = Path(__file__).resolve().parents[1] / 'alerts' / 'portscan_alerts.json'
first_timestamp = None
last_timestamp = None

# ==========================================
# LANCEMENT TSHARK
# ==========================================

command = [
    TSHARK_PATH,
    "-n",
    "-r", PCAP_PATH,
    "-Y", "ip && (tcp.flags.syn == 1 && tcp.flags.ack == 0 || ftp.response.code == 227)",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.dstport",
    "-e", "ftp.response.code",
    "-e", "ftp.response.arg"
]

print("--- DARKTRACE LAB : PORTSCAN DETECTOR ---")
print("Fenêtre temporelle :", WINDOW_SECONDS, "secondes")
print("Seuil de ports :", PORT_THRESHOLD)
print("Limite de SYN :", MAX_SYN_PACKETS)
process = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    encoding="utf-8",
    errors="replace"
)

try:
    for line in process.stdout:
        if MAX_SYN_PACKETS is not None and syn_count >= MAX_SYN_PACKETS:
            break
        fields = line.rstrip("\r\n").split("\t")

        if len(fields) != 6:
            continue

        try:
            timestamp = float(fields[0])
        except ValueError:
            continue

        src = fields[1]
        dst = fields[2]
        dst_port = fields[3]
        ftp_code = fields[4]
        ftp_arg = fields[5]

        # 1. Réponse FTP passive du serveur
        if ftp_code == "227":
            match = re.search(
                r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)",
                ftp_arg
            )

            if match:
                values = [int(v) for v in match.groups()]

                if all(0 <= v <= 255 for v in values):
                    announced_ip = ".".join(
                        str(v) for v in values[:4]
                    )
                    announced_port = values[4] * 256 + values[5]

                    # Le serveur annonce un port au client.
                    key = (dst, announced_ip, announced_port)

                    ftp_passive_ports[key] = timestamp

            continue

        # 2. Tentative de connexion TCP SYN
        if not dst_port:
            continue

        try:
            port = int(dst_port)
        except ValueError:
            continue

        syn_count += 1

        if first_timestamp is None:
            first_timestamp = timestamp

        last_timestamp = timestamp

        # 3. Vérifier si le port a été annoncé par FTP
        ftp_key = (src, dst, port)
        announced_at = ftp_passive_ports.get(ftp_key)

        if (
            announced_at is not None
            and 0 <= timestamp - announced_at <= 30
        ):
            ftp_explained_count += 1
            continue

        # 4. Analyser les ports non expliqués
        key = (src, dst)
        history = connections[key]

        history.append((timestamp, port))

        while history and timestamp - history[0][0] > WINDOW_SECONDS:
            history.popleft()

        unique_ports = {p for _, p in history}

        max_ports_seen[key] = max(
            max_ports_seen[key],
            len(unique_ports)
        )

        if (
            len(unique_ports) >= PORT_THRESHOLD
            and key not in alerted
        ):
            alerted.add(key)
            alert_count += 1
            alerts.append({
                "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                "detector": "PORT_SCAN",
                "severity": "HIGH",
                "source_ip": src,
                "destination_ip": dst,
                "distinct_ports_per_window": len(unique_ports),
                "window_seconds": WINDOW_SECONDS,
                "threshold": PORT_THRESHOLD,
                "status": "POTENTIAL_ATTACK",
            })

            print("\n[ALERTE PORTSCAN POTENTIEL]")
            print("Date :", datetime.fromtimestamp(timestamp))
            print("Source :", src)
            print("Destination :", dst)
            print("Ports distincts :", len(unique_ports))


    else:
        exit_code = process.wait()
        if exit_code != 0:
            raise SystemExit(f"TShark a échoué (code {exit_code}).")

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


# ==========================================
# CORRÉLATION FTP
# ==========================================

print("\n--- CORRÉLATION FTP ---")
print("Ports FTP annoncés :", len(ftp_passive_ports))
print("Tentatives SYN expliquées par FTP :", ftp_explained_count)
print("Tentatives SYN non expliquées :", syn_count - ftp_explained_count)     

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

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_PATH.open("w", encoding="utf-8") as output_file:
    json.dump(alerts, output_file, ensure_ascii=False, indent=4)
    output_file.write("\n")

print("Alertes enregistrées :", OUTPUT_PATH)