
import pandas as pd

# ==========================================
# VÉRIFICATION DES MÉTADONNÉES RÉSEAU
# ==========================================

datasets = {
    "PortScan": (
        "data/raw/MachineLearningCSV/MachineLearningCVE/"
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    ),
    "DDoS": (
        "data/raw/MachineLearningCSV/MachineLearningCVE/"
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ),
    "Wednesday": (
        "data/raw/MachineLearningCSV/MachineLearningCVE/"
        "Wednesday-workingHours.pcap_ISCX.csv"
    )
}

keywords = [
    "ip",
    "port",
    "timestamp",
    "time",
    "protocol",
    "flow id"
]

for name, path in datasets.items():

    # Lire uniquement les en-têtes
    df = pd.read_csv(path, nrows=0)

    columns = df.columns.str.strip().tolist()

    print(f"\n--- {name} ---")

    print("Nombre de colonnes :", len(columns))

    print("\nColonnes réseau et temporelles :")

    for column in columns:

        if any(
            keyword in column.lower()
            for keyword in keywords
        ):
            print("-", column)
