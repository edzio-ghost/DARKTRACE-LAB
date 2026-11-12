
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
# CHARGEMENT DES DONNÉES
# ==========================================

file_path = (
    "data/raw/MachineLearningCSV/MachineLearningCVE/"
    "Wednesday-workingHours.pcap_ISCX.csv"
)

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

df = df[features + ["Label"]].copy()

df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

X = df[features]

# ==========================================
# PRÉDICTIONS ET PROBABILITÉS
# ==========================================

predictions = model.predict(X)
probabilities = model.predict_proba(X)

# Probabilité la plus élevée parmi les classes connues
confidence = probabilities.max(axis=1)

df["Prediction"] = predictions
df["Confidence"] = confidence

print("--- CONFIANCE DES PRÉDICTIONS ---")

attack_labels = [
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "Heartbleed"
]

for attack in attack_labels:

    subset = df[df["Label"] == attack]

    if len(subset) == 0:
        continue

    missed = subset[subset["Prediction"] == "BENIGN"]
    flagged = subset[subset["Prediction"] != "BENIGN"]

    print(f"\n--- {attack} ---")
    print("Flux :", len(subset))
    print("Non signalés :", len(missed))
    print("Signalés :", len(flagged))

    if len(missed) > 0:
        print(
            "Confiance moyenne des flux non signalés :",
            round(missed["Confidence"].mean(), 4)
        )

        print(
            "Flux non signalés avec confiance >= 0.90 :",
            int((missed["Confidence"] >= 0.90).sum())
        )

        print(
            "Flux non signalés avec confiance >= 0.99 :",
            int((missed["Confidence"] >= 0.99).sum())
        )

    if len(flagged) > 0:
        print(
            "Confiance moyenne des flux signalés :",
            round(flagged["Confidence"].mean(), 4)
        )

# ==========================================
# ANALYSE DU TRAFIC BENIGN
# ==========================================

benign = df[df["Label"] == "BENIGN"]

correct = benign[benign["Prediction"] == "BENIGN"]

print("\n--- BENIGN CORRECTEMENT RECONNU ---")

print("Flux :", len(correct))

print(
    "Confiance moyenne :",
    round(correct["Confidence"].mean(), 4)
)

print(
    "Confiance médiane :",
    round(correct["Confidence"].median(), 4)
)
