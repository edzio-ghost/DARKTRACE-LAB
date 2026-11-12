
import subprocess
import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timezone

# --- CONFIGURATION ---
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
PCAP_PATH = r"data\pcap\Friday-WorkingHours.pcap"
OUTPUT_PATH = Path("alerts/http_flood_alerts.json")

# Seuils exploratoires, à valider sur des données distinctes
WINDOW_SECONDS = 60
REQUEST_THRESHOLD = 3000
ALERT_COOLDOWN = 60

# --- INITIALISATION ---
requests = defaultdict(deque)
last_alert = {}
max_requests = defaultdict(int)

total_requests = 0
alert_count = 0
alerts = []

command = [
    TSHARK_PATH,
    "-n",
    "-r", PCAP_PATH,
    "-Y", "ip && http.request.method == GET",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "http.request.uri",
]

print("--- DARKTRACE LAB : HTTP FLOOD DETECTOR ---")
print(f"Fenêtre : {WINDOW_SECONDS} secondes")
print(f"Seuil : {REQUEST_THRESHOLD} GET / fenêtre")
print()

# --- ANALYSE DU TRAFIC ---
process = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    encoding="utf-8",
    errors="replace"
)

try:
    for line in process.stdout:
        fields = line.rstrip("\r\n").split("\t", 3)

        if len(fields) != 4:
            continue

        try:
            timestamp = float(fields[0])
        except ValueError:
            continue

        src = fields[1]
        dst = fields[2]
        uri = fields[3]

        if not src or not dst:
            continue

        total_requests += 1
        key = (src, dst)

        history = requests[key]
        history.append(timestamp)

        # Fenêtre glissante de 60 secondes
        while history and timestamp - history[0] > WINDOW_SECONDS:
            history.popleft()

        count = len(history)

        if count > max_requests[key]:
            max_requests[key] = count

        # Détection et limitation des alertes répétées
        if count >= REQUEST_THRESHOLD:
            previous_alert = last_alert.get(key)

            if (
                previous_alert is None
                or timestamp - previous_alert >= ALERT_COOLDOWN
            ):
                alert_count += 1
                last_alert[key] = timestamp

                event_time = datetime.fromtimestamp(
                    timestamp, tz=timezone.utc
                ).isoformat()

                # Alerte structurée pour le futur dashboard
                alert = {
                    "timestamp": event_time,
                    "detector": "HTTP_FLOOD",
                    "severity": "HIGH",
                    "source_ip": src,
                    "destination_ip": dst,
                    "destination_port": 80,
                    "requests_per_window": count,
                    "window_seconds": WINDOW_SECONDS,
                    "threshold": REQUEST_THRESHOLD,
                    "uri": uri,
                    "status": "POTENTIAL_ATTACK"
                }

                alerts.append(alert)

                print("\n[ALERTE HTTP FLOOD POTENTIEL]")
                print(f"Heure UTC : {event_time}")
                print(f"Source : {src}")
                print(f"Destination : {dst}")
                print(
                    f"GET dans les {WINDOW_SECONDS} "
                    f"dernières secondes : {count}"
                )
                print(f"URI actuelle : {uri}")

finally:
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

# --- RÉSULTATS ---
print("\n--- RÉSULTATS ---")
print(f"Total GET analysés : {total_requests}")
print(f"Alertes générées : {alert_count}")

print("\n--- TOP 10 DES FLUX HTTP ---")

top_flows = sorted(
    max_requests.items(),
    key=lambda item: item[1],
    reverse=True
)[:10]

for (src, dst), maximum in top_flows:
    print(
        f"{src} -> {dst} | "
        f"Maximum GET / 60s : {maximum}"
    )

# --- EXPORT JSON ---
OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)

with OUTPUT_PATH.open("w", encoding="utf-8") as f:
    json.dump(
        alerts,
        f,
        indent=4,
        ensure_ascii=False
    )

print("\n--- EXPORT JSON ---")
print(f"Fichier : {OUTPUT_PATH}")
print(f"Alertes enregistrées : {len(alerts)}")
