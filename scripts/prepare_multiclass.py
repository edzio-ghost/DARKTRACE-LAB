
import pandas as pd
import numpy as np

# Chemins des datasets
portscan_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

ddos_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

# Charger les datasets
portscan = pd.read_csv(portscan_path)
ddos = pd.read_csv(ddos_path)

# Nettoyer les noms des colonnes
portscan.columns = portscan.columns.str.strip()
ddos.columns = ddos.columns.str.strip()

# Sélectionner les caractéristiques
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow IAT Mean",
    "Flow Packets/s"
]

# Conserver les caractéristiques et les étiquettes
columns = features + ["Label"]

portscan = portscan[columns]
ddos = ddos[columns]

# Fusionner les datasets
df = pd.concat(
    [portscan, ddos],
    ignore_index=True
)

# Nettoyage des données
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

# Réinitialiser les index
df = df.reset_index(drop=True)

print("--- DATASET MULTICLASSE ---")

print("Dimensions :", df.shape)

print("\nRépartition des classes :")
print(df["Label"].value_counts())

print("\nPourcentages :")
print(
    df["Label"].value_counts(normalize=True) * 100
)

# Sauvegarder le dataset
df.to_csv(
    "data/processed/multiclass.csv",
    index=False
)

print("\nDataset sauvegardé : data/processed/multiclass.csv")
