
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent

SCRIPTS = [
    ("PORT SCAN DETECTOR", "detect_portscan_tshark.py"),
    ("HTTP FLOOD DETECTOR", "detect_http_flood.py"),
    ("CORRELATION ENGINE", "correlate_alerts.py"),
]


def run_script(name, filename):
    path = ROOT / "scripts" / filename

    print(f"\n{'=' * 55}", flush=True)
    print(f"DARKTRACE LAB | {name}", flush=True)
    print(f"{'=' * 55}\n", flush=True)

    if not path.is_file():
        raise FileNotFoundError(f"Script introuvable : {path}")

    result = subprocess.run(
        [sys.executable, str(path)],
        cwd=ROOT,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{name} a échoué (code {result.returncode})"
        )


def main():
    started = datetime.now(timezone.utc)

    print("DARKTRACE LAB - IDS ENGINE", flush=True)
    print(f"Démarrage UTC : {started.isoformat()}", flush=True)

    try:
        for name, filename in SCRIPTS:
            run_script(name, filename)

    except (OSError, RuntimeError) as error:
        print(f"\n[ERREUR] {error}", file=sys.stderr)
        return 1

    duration = datetime.now(timezone.utc) - started

    print("\n" + "=" * 55)
    print("ANALYSE TERMINÉE")
    print(f"Durée totale : {duration}")
    print("Rapport : alerts/incidents.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
