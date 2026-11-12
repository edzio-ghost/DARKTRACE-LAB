
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    confusion_matrix,
    roc_auc_score,
    average_precision_score
)

# Charger le dataset du vendredi
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Nettoyer les données
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

# Véritables étiquettes
y_true = (df["Label"] == "PortScan").astype(int)

# Caractéristiques du premier modèle
features_v1 = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Destination Port"
]

# Caractéristiques supplémentaires de V2
features_v2 = features_v1 + [
    "Flow IAT Mean",
    "Flow Packets/s"
]

# Charger les deux modèles
model_v1 = joblib.load("models/isolation_forest.pkl")
model_v2 = joblib.load("models/isolation_forest_v2.pkl")

# Comparer les modèles
models = [
    ("V1", model_v1, features_v1),
    ("V2", model_v2, features_v2)
]

for name, model, features in models:

    X = df[features]

    # Prédire les anomalies
    predictions = model.predict(X)
    y_pred = (predictions == -1).astype(int)

    # Calculer les scores de suspicion
    scores = -model.decision_function(X)

    # Calculer la matrice de confusion
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred
    ).ravel()

    # Calculer les métriques
    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)
    auc = roc_auc_score(y_true, scores)
    ap = average_precision_score(y_true, scores)

    print(f"\n--- DARKTRACE LAB {name} ---")
    print("Attaques détectées :", tp)
    print("Attaques manquées :", fn)
    print("Fausses alertes :", fp)
    print(f"Taux de détection : {recall * 100:.4f}%")
    print(f"Taux de fausses alertes : {fpr * 100:.2f}%")
    print(f"ROC-AUC : {auc:.4f}")
    print(f"Average Precision : {ap:.4f}")
