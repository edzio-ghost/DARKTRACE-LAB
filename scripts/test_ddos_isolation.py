
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import roc_auc_score, average_precision_score

# Charger le dataset DDoS
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Nettoyage des données
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

# Caractéristiques utilisées par Isolation Forest V2
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Destination Port",
    "Flow IAT Mean",
    "Flow Packets/s"
]

# Charger Isolation Forest V2
model = joblib.load("models/isolation_forest_v2.pkl")

X = df[features]

# Prédictions :
# 1 = Normal
# -1 = Anomalie
predictions = model.predict(X)

# Identifier les classes réelles
benign_mask = df["Label"] == "BENIGN"
ddos_mask = df["Label"] == "DDoS"

# Calculer les taux de détection
benign_alerts = (predictions[benign_mask] == -1).sum()
ddos_detected = (predictions[ddos_mask] == -1).sum()

false_alert_rate = benign_alerts / benign_mask.sum()
ddos_detection_rate = ddos_detected / ddos_mask.sum()

print("--- TEST ISOLATION FOREST V2 SUR DDOS ---")

print("Flux BENIGN :", benign_mask.sum())
print("Flux DDoS :", ddos_mask.sum())

print("\n--- RESULTATS ---")

print("Fausses alertes BENIGN :", benign_alerts)
print("DDoS détectés :", ddos_detected)
print("DDoS non détectés :", ddos_mask.sum() - ddos_detected)

print(
    f"Taux de fausses alertes : "
    f"{false_alert_rate * 100:.2f}%"
)

print(
    f"Taux de détection DDoS : "
    f"{ddos_detection_rate * 100:.2f}%"
)

# ==========================================
# ANALYSE DES SCORES D'ANOMALIE
# ==========================================

print("\n--- SCORES D'ANOMALIE ---")

# Calculer les scores continus
#Score négatif : anomalie selon le seuil actuel.
#Score positif : observation considérée comme normale.
#Plus le score est faible, plus le modèle considère le flux comme inhabituel
scores = model.decision_function(X)

# Séparer les scores selon la classe réelle
benign_scores = scores[benign_mask]
ddos_scores = scores[ddos_mask]

print("\nTrafic BENIGN :")
print("Moyenne :", benign_scores.mean())
print("Médiane :", np.median(benign_scores))
print("Minimum :", benign_scores.min())
print("Maximum :", benign_scores.max())

print("\nTrafic DDoS :")
print("Moyenne :", ddos_scores.mean())
print("Médiane :", np.median(ddos_scores))
print("Minimum :", ddos_scores.min())
print("Maximum :", ddos_scores.max())

# ==========================================
# PERFORMANCE DES SCORES
# ==========================================



# 1 = DDoS
# 0 = BENIGN
y_true = (df["Label"] == "DDoS").astype(int)

# Inverser les scores :
# plus la valeur est élevée, plus le flux est suspect
anomaly_scores = -scores

print("\n--- CAPACITÉ DE DISTINCTION ---")

print(
    "ROC-AUC :",
    roc_auc_score(y_true, anomaly_scores)
)

print(
    "Average Precision :",
    average_precision_score(y_true, anomaly_scores)
)
