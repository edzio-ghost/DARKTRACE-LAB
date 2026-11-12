
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import confusion_matrix

# Charger le modèle Random Forest entraîné sur PortScan
saved = joblib.load("models/random_forest_portscan.pkl")

model = saved["model"]
features = saved["features"]

# Charger le dataset DDoS
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Nettoyage des données
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

print("--- TEST SUR DDOS ---")
print("Flux après nettoyage :", len(df))

print("\nRépartition des classes :")
print(df["Label"].value_counts())

# Sélectionner les mêmes caractéristiques que pendant l'entraînement
X = df[features]

# 0 = BENIGN
# 1 = DDoS
y_true = (df["Label"] == "DDoS").astype(int)

# Prédictions du modèle
# 0 = BENIGN
# 1 = PortScan
predictions = model.predict(X)

# Afficher la matrice de signalement
print("\n--- MATRICE DE SIGNALEMENT ---")

print(
    confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1]
    )
)

# Séparer les flux normaux et les attaques DDoS
benign_mask = y_true == 0
ddos_mask = y_true == 1

# Calculer les taux de signalement
false_alert_rate = predictions[benign_mask].mean()
ddos_flag_rate = predictions[ddos_mask].mean()

print("\n--- RESULTATS ---")

print(
    f"Trafic BENIGN signalé PortScan : "
    f"{false_alert_rate * 100:.2f}%"
)

print(
    f"Trafic DDoS signalé PortScan : "
    f"{ddos_flag_rate * 100:.2f}%"
)

print(
    f"Flux DDoS non signalés : "
    f"{(predictions[ddos_mask] == 0).sum()}"
)
