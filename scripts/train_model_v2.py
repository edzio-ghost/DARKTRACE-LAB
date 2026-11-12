
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# Charger le trafic normal nettoyé
df = pd.read_csv("data/processed/monday_clean.csv")

# Caractéristiques de DARKTRACE LAB V2
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Destination Port",
    "Flow IAT Mean",
    "Flow Packets/s"
]

X = df[features]

# Séparer les données
X_train, X_test = train_test_split(
    X,
    test_size=0.2,
    random_state=42
)

# Créer le modèle V2
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,
    random_state=42,
    n_jobs=-1
)

print("Entraînement DARKTRACE LAB V2...")
model.fit(X_train)

# Évaluer les alertes sur le trafic normal
predictions = model.predict(X_test)
false_positives = (predictions == -1).sum()

print("\n--- RÉSULTATS V2 SUR LE LUNDI ---")
print("Flux testés :", len(X_test))
print("Fausses alertes :", false_positives)
print(f"Taux de fausses alertes : {false_positives / len(X_test) * 100:.2f}%")

# Sauvegarder le nouveau modèle
Path("models").mkdir(exist_ok=True)
joblib.dump(model, "models/isolation_forest_v2.pkl")

print("\nModèle V2 sauvegardé.")
