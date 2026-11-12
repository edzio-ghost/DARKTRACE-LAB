
import json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
ALERTS_DIR = ROOT / "alerts"

INPUT_FILES = [
    ALERTS_DIR / "http_flood_alerts.json",
    ALERTS_DIR / "portscan_alerts.json",
]

OUTPUT_PATH = ALERTS_DIR / "incidents.json"
MAX_GAP_SECONDS = 120

alerts = []

for path in INPUT_FILES:
    if not path.exists():
        raise FileNotFoundError(f"Fichier manquant : {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Format JSON incorrect : {path}")

    alerts.extend(data)

alerts.sort(
    key=lambda alert: datetime.fromisoformat(
        alert["timestamp"]
    )
)

incidents = []

for alert in alerts:
    timestamp = datetime.fromisoformat(alert["timestamp"])
    matching_incident = None

    for incident in incidents:
        same_flow = (
            incident["detector"] == alert["detector"]
            and incident["source_ip"] == alert["source_ip"]
            and incident["destination_ip"]
            == alert["destination_ip"]
        )

        last_seen = datetime.fromisoformat(
            incident["last_seen"]
        )
        gap = (timestamp - last_seen).total_seconds()

        if same_flow and 0 <= gap <= MAX_GAP_SECONDS:
            matching_incident = incident
            break

    if matching_incident is None:
        matching_incident = {
            "incident_id": f"INC-{len(incidents) + 1:04d}",
            "detector": alert["detector"],
            "severity": alert["severity"],
            "source_ip": alert["source_ip"],
            "destination_ip": alert["destination_ip"],
            "first_seen": alert["timestamp"],
            "last_seen": alert["timestamp"],
            "alert_count": 0,
            "max_requests_per_window": None,
            "max_distinct_ports_per_window": None,
            "status": "OPEN",
        }
        incidents.append(matching_incident)

    matching_incident["last_seen"] = alert["timestamp"]
    matching_incident["alert_count"] += 1

    if "requests_per_window" in alert:
        previous = (
            matching_incident["max_requests_per_window"] or 0
        )
        matching_incident["max_requests_per_window"] = max(
            previous,
            alert["requests_per_window"]
        )

    if "distinct_ports_per_window" in alert:
        previous = (
            matching_incident["max_distinct_ports_per_window"]
            or 0
        )
        matching_incident["max_distinct_ports_per_window"] = max(
            previous,
            alert["distinct_ports_per_window"]
        )

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_PATH.open("w", encoding="utf-8") as f:
    json.dump(incidents, f, indent=4, ensure_ascii=False)

print("--- DARKTRACE LAB : CORRELATION ENGINE ---")
print(f"Alertes analysées : {len(alerts)}")
print(f"Incidents créés : {len(incidents)}")

for incident in incidents:
    print(f"\n[{incident['incident_id']}]")
    print(f"Type : {incident['detector']}")
    print(f"Source : {incident['source_ip']}")
    print(f"Destination : {incident['destination_ip']}")
    print(f"Alertes regroupées : {incident['alert_count']}")
    print(f"Début : {incident['first_seen']}")
    print(f"Fin : {incident['last_seen']}")

print(f"\nIncidents enregistrés : {OUTPUT_PATH}")
