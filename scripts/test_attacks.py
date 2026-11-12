
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.metrics import roc_auc_score, average_precision_score

# Charger les données du vendredi
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

df = pd.read_csv(file_path)

# Nettoyer les noms des colonnes
df.columns = df.columns.str.strip()

# Afficher les informations
print("--- DATASET PORTSCAN ---")
print("Dimensions :", df.shape)

print("\nTypes de trafic :")
print(df["Label"].value_counts())


# Nettoyer les données du vendredi
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

print("\nFlux conservés après nettoyage :", len(df))

# Charger le modèle entraîné
model = joblib.load("models/isolation_forest.pkl")

# Utiliser exactement les mêmes caractéristiques
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Destination Port"
]

X_test = df[features]

# Prédictions du modèle envoie 1 pour normaux et -1 pour anomalies
predictions = model.predict(X_test)

# Convertir les prédictions en 0 et 1
# 0 = normal, 1 = anomalie
y_pred = (predictions == -1).astype(int)

# Véritables étiquettes
# 0 = BENIGN, 1 = PortScan
y_true = (df["Label"] == "PortScan").astype(int)

# Évaluer les résultats
print("\n--- MATRICE DE CONFUSION ---")
print(confusion_matrix(y_true, y_pred))

print("\n--- RAPPORT DE CLASSIFICATION ---")
print(classification_report(
    y_true,
    y_pred,
    target_names=["BENIGN", "PortScan"],
    zero_division=0
))
# Calculer les scores d'anomalie
scores = model.decision_function(X_test)

# Ajouter les scores au DataFrame
df["Anomaly Score"] = scores

# Comparer les scores selon le type de trafic
print("\n--- SCORES D'ANOMALIE ---")

print(
    df.groupby("Label")["Anomaly Score"]
    .describe()
    .to_string()
)# Inverser les scores :
# plus la valeur est élevée, plus le flux est suspect
anomaly_scores = -scores

# Mesurer la séparation entre BENIGN et PortScan
auc = roc_auc_score(y_true, anomaly_scores)

# Mesurer la précision moyenne sur les différents seuils
ap = average_precision_score(y_true, anomaly_scores)

print("\n--- ÉVALUATION DES SCORES ---")
print(f"ROC-AUC : {auc:.4f}")
print(f"Average Precision : {ap:.4f}")


# Caractéristiques à comparer
comparison_features = [
    "SYN Flag Count",
    "RST Flag Count",
    "Flow IAT Mean",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets"
]

print("\n--- COMPARAISON BENIGN / PORTSCAN ---")

# Calculer les médianes par type de trafic
comparison = df.groupby("Label")[comparison_features].median()

print(comparison.to_string())
