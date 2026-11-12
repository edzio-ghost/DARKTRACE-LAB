
import pandas as pd
import numpy as np
import joblib

# ==========================================
# CHARGEMENT DU MODÈLE
# ==========================================

saved = joblib.load("models/random_forest_multiclass.pkl")

model = saved["model"]
features = saved["features"]

# ==========================================
# CHARGEMENT DU DATASET
# ==========================================

file_path = (
    "data/raw/MachineLearningCSV/MachineLearningCVE/"
    "Wednesday-workingHours.pcap_ISCX.csv"
)

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

print("--- DATASET MERCREDI ---")
print("Flux avant nettoyage :", len(df))

# Nettoyer uniquement les colonnes nécessaires
df = df[features + ["Label"]].copy()

df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

print("Flux après nettoyage :", len(df))

print("\nClasses réelles :")
print(df["Label"].value_counts())

# ==========================================
# PRÉDICTIONS
# ==========================================

X = df[features]

predictions = model.predict(X)

df["Prediction"] = predictions

print("\n--- MATRICE DES PRÉDICTIONS ---")

table = pd.crosstab(
    df["Label"],
    df["Prediction"]
)

table = table.reindex(
    columns=["BENIGN", "PortScan", "DDoS"],
    fill_value=0
)

print(table.to_string())

# ==========================================
# ANALYSE PAR FAMILLE
# ==========================================

print("\n--- DÉTECTION DES ATTAQUES INCONNUES ---")

attack_labels = [
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "Heartbleed"
]

for attack in attack_labels:

    subset = df[df["Label"] == attack]

    total = len(subset)

    if total == 0:
        print(f"\n{attack} : aucun flux exploitable")
        continue

    # Le modèle ne connaît pas ces attaques.
    # Une prédiction PortScan ou DDoS est donc
    # seulement considérée comme un signalement.
    flagged = (subset["Prediction"] != "BENIGN").sum()

    rate = flagged / total * 100

    print(f"\n{attack}")
    print("Flux :", total)
    print("Flux signalés :", flagged)
    print(f"Taux de signalement : {rate:.2f}%")

# ==========================================
# FAUSSES ALERTES SUR LE TRAFIC NORMAL
# ==========================================

print("\n--- FAUSSES ALERTES BENIGN ---")

benign = df[df["Label"] == "BENIGN"]

false_alerts = (benign["Prediction"] != "BENIGN").sum()

false_alert_rate = false_alerts / len(benign) * 100

print("Flux BENIGN :", len(benign))
print("Fausses alertes :", false_alerts)
print(f"Taux de fausses alertes : {false_alert_rate:.2f}%")
