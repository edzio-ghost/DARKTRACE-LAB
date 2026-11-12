
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

# Charger le dataset PortScan
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Nettoyer les données
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

# Sélectionner les caractéristiques
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

# Définir les étiquettes
# 0 = BENIGN, 1 = PortScan
y = (df["Label"] == "PortScan").astype(int)

# Séparer les données
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("--- PRÉPARATION RANDOM FOREST ---")
print("Flux pour entraînement :", len(X_train))
print("Flux pour test :", len(X_test))

print("\nRépartition entraînement :")
print(y_train.value_counts())

print("\nRépartition test :")
print(y_test.value_counts())


# Créer notre modèle Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

print("\nEntraînement Random Forest en cours...")

# Entraîner le modèle avec les flux et leurs étiquettes
model.fit(X_train, y_train)

print("Entraînement terminé !")

# Tester le modèle sur les données non utilisées
# pendant l'entraînement
predictions = model.predict(X_test)

# Calculer la matrice de confusion
print("\n--- MATRICE DE CONFUSION RANDOM FOREST ---")
print(confusion_matrix(y_test, predictions))

# Afficher les métriques
print("\n--- RAPPORT DE CLASSIFICATION ---")
print(classification_report(
    y_test,
    predictions,
    target_names=["BENIGN", "PortScan"]
))

# Récupérer l'importance des caractéristiques
importances = model.feature_importances_

# Associer chaque caractéristique à son importance
feature_importance = pd.DataFrame({
    "Feature": features,
    "Importance": importances
})

# Trier de la plus importante à la moins importante
feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\n--- IMPORTANCE DES CARACTÉRISTIQUES ---")
print(feature_importance.to_string(index=False))

# Créer une liste sans Destination Port
features_without_port = [
    feature for feature in features
    if feature != "Destination Port"
]

# Garder les mêmes données d'entraînement et de test
X_train_no_port = X_train[features_without_port]
X_test_no_port = X_test[features_without_port]

# Créer un nouveau modèle Random Forest
model_no_port = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

print("\nEntraînement sans Destination Port...")

# Entraîner le nouveau modèle
model_no_port.fit(X_train_no_port, y_train)

print("Entraînement terminé !")

# Faire les prédictions
predictions_no_port = model_no_port.predict(X_test_no_port)

# Afficher les résultats
print("\n--- RANDOM FOREST SANS DESTINATION PORT ---")

print(confusion_matrix(y_test, predictions_no_port))

print(classification_report(
    y_test,
    predictions_no_port,
    target_names=["BENIGN", "PortScan"],
    digits=4
))

# ==========================================
# ANALYSE DE L'ORDRE DES FLUX
# ==========================================

print("\n--- ANALYSE CHRONOLOGIQUE ---")

# Vérifier si une colonne Timestamp existe
print("Colonne Timestamp présente :", "Timestamp" in df.columns)

# Observer la répartition des étiquettes
# dans les différentes parties du dataset
df_order = df.reset_index(drop=True).copy()

df_order["Bloc"] = pd.qcut(
    df_order.index,
    q=5,
    labels=["Bloc 1", "Bloc 2", "Bloc 3", "Bloc 4", "Bloc 5"]
)

print("\nRépartition des classes par bloc :")

print(
    pd.crosstab(
        df_order["Bloc"],
        df_order["Label"]
    ).to_string()
)
