
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

# Charger le dataset
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Nettoyage
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df[df["Flow Duration"] >= 0]

# Réinitialiser les index sans mélanger les lignes
df = df.reset_index(drop=True)

# Caractéristiques sans Destination Port
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow IAT Mean",
    "Flow Packets/s"
]

X = df[features]
y = (df["Label"] == "PortScan").astype(int)

# Séparer les quatre premiers blocs du dernier
split_index = int(len(df) * 0.8)

X_train = X.iloc[:split_index]
X_test = X.iloc[split_index:]

y_train = y.iloc[:split_index]
y_test = y.iloc[split_index:]

print("--- SÉPARATION PAR BLOCS ---")
print("Entraînement :", len(X_train))
print("Test :", len(X_test))

print("\nClasses entraînement :")
print(y_train.value_counts())

print("\nClasses test :")
print(y_test.value_counts())

# Entraîner Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

print("\nEntraînement en cours...")
model.fit(X_train, y_train)

# Tester sur le dernier bloc
predictions = model.predict(X_test)

print("\n--- MATRICE DE CONFUSION PAR BLOCS ---")
print(confusion_matrix(y_test, predictions))

print("\n--- RAPPORT DE CLASSIFICATION PAR BLOCS ---")
print(classification_report(
    y_test,
    predictions,
    target_names=["BENIGN", "PortScan"],
    digits=4
))

# ==========================================
# RECHERCHE DE DOUBLONS ENTRE TRAIN ET TEST
# ==========================================

print("\n--- ANALYSE DES DOUBLONS ---")

# Nombre de lignes dupliquées dans le dataset
#compte les lignes qui possèdent les mêmes valeurs sur les six caractéristiques sélectionnées
duplicates = X.duplicated().sum()

print("Flux dupliqués dans le dataset :", duplicates)
print(f"Pourcentage : {duplicates / len(X) * 100:.2f}%")

# Construire un ensemble de signatures des flux
train_signatures = pd.util.hash_pandas_object(
    X_train,
    index=False
)

test_signatures = pd.util.hash_pandas_object(
    X_test,
    index=False
)

# Vérifier quelles signatures du test existent
# également dans l'entraînement
common = test_signatures.isin(
    set(train_signatures)
)

print("\nFlux du test identiques à un flux d'entraînement :")
print(common.sum())

print(f"Pourcentage du test : {common.mean() * 100:.2f}%")

# Comparer selon les véritables étiquettes
print("\nDoublons du test par classe :")

print(
    pd.crosstab(
        y_test,
        common,
        rownames=["Classe"],
        colnames=["Présent dans train"]
    ).to_string()
)
