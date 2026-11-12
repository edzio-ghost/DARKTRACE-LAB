
import pandas as pd
import numpy as np
import joblib

# Charger le modèle multiclasse
saved = joblib.load("models/random_forest_multiclass.pkl")

model = saved["model"]
features = saved["features"]

# Charger le dataset BENIGN du lundi
file_path = "data/processed/monday_clean.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Nettoyage des données
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

print("--- TEST SUR LE TRAFIC DU LUNDI ---")

print("Flux analysés :", len(df))

print("\nClasses réelles :")
print(df["Label"].value_counts())

# Sélectionner les mêmes caractéristiques
X = df[features]

# Effectuer les prédictions
predictions = model.predict(X)

# Compter les prédictions
results = pd.Series(predictions).value_counts()

print("\n--- PRÉDICTIONS DU MODÈLE ---")
print(results)

# Calculer le taux de reconnaissance BENIGN
benign_detected = (predictions == "BENIGN").sum()

benign_rate = benign_detected / len(predictions)

# Calculer les fausses alertes
false_alerts = (predictions != "BENIGN").sum()

false_alert_rate = false_alerts / len(predictions)

print("\n--- RESULTATS ---")

print("Flux BENIGN correctement reconnus :", benign_detected)
print("Fausses alertes :", false_alerts)

print(
    f"Taux de reconnaissance BENIGN : "
    f"{benign_rate * 100:.2f}%"
)

print(
    f"Taux de fausses alertes : "
    f"{false_alert_rate * 100:.2f}%"
)
