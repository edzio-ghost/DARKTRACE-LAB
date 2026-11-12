
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from pathlib import Path

# Charger le dataset nettoyé
df = pd.read_csv("data/processed/monday_clean.csv")

# Sélectionner les caractéristiques réseau
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Destination Port"
]

#Sélectionne les cinq caractéristiques qui seront fournies au modèle
X = df[features]

# Séparer les données : 80 % entraînement, 20 % test
X_train, X_test = train_test_split(
    X,
    test_size=0.2,
    # fixe la répartition aléatoire afin de retrouver les mêmes résultats à chaque exécution
    random_state=42
)

print("--- PRÉPARATION MACHINE LEARNING ---")
print("Nombre total de flux :", len(X))
print("Flux pour entraînement :", len(X_train))
print("Flux pour test :", len(X_test))
print("\nCaractéristiques utilisées :")
print(X.columns.tolist())

# Créer notre modèle de détection d'anomalies
model = IsolationForest(
    #Construit 100 arbres d'isolation
    n_estimators=100,
    #Fixe le seuil de décision en supposant environ 1 % d'anomalies dans les données d'entraînement
    contamination=0.01,
    #Rend les résultats reproductibles
    random_state=42,
    #Utilise les cœurs CPU disponibles pour paralléliser le travail
    n_jobs=-1
)

# Entraîner le modèle sur le trafic normal
print("\nEntraînement en cours...")
model.fit(X_train)

print("Entraînement terminé !")

# Prédire les anomalies dans les données de test
predictions = model.predict(X_test)

# Compter les résultats
normal_count = (predictions == 1).sum()
anomaly_count = (predictions == -1).sum()

print("\n--- RÉSULTATS DU MODÈLE ---")
print("Flux considérés comme normaux :", normal_count)
print("Flux considérés comme anormaux :", anomaly_count)

# Calculer le pourcentage de fausses alertes
false_positive_rate = anomaly_count / len(X_test) * 100

print(f"Taux de fausses alertes : {false_positive_rate:.2f}%")

# Créer le dossier pour les modèles
model_dir = Path("models")
model_dir.mkdir(exist_ok=True)

# Sauvegarder le modèle entraîné dans le fichier .pkl
joblib.dump(model, model_dir / "isolation_forest.pkl")

print("\nModèle sauvegardé : models/isolation_forest.pkl")
