
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import GroupShuffleSplit
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

# Construire une signature pour chaque combinaison
# de caractéristiques
groups = pd.util.hash_pandas_object(
    X,
    index=False
)

# Séparer les groupes, pas les lignes individuellement
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.2,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

print("--- SÉPARATION SANS SIGNATURES COMMUNES ---")
print("Entraînement :", len(X_train))
print("Test :", len(X_test))

print("\nClasses entraînement :")
print(y_train.value_counts())

print("\nClasses test :")
print(y_test.value_counts())

# Vérifier l'absence de signatures communes
train_groups = set(groups.iloc[train_idx])
test_groups = set(groups.iloc[test_idx])

print("\nSignatures communes :", len(train_groups & test_groups))

# Entraîner le modèle
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

print("\nEntraînement en cours...")
model.fit(X_train, y_train)

# Évaluer
predictions = model.predict(X_test)

print("\n--- MATRICE DE CONFUSION SANS DOUBLONS ---")
print(confusion_matrix(y_test, predictions))

print("\n--- RAPPORT DE CLASSIFICATION SANS DOUBLONS ---")
print(classification_report(
    y_test,
    predictions,
    target_names=["BENIGN", "PortScan"],
    digits=4,
    zero_division=0
))

# ==========================================
# ANALYSE DES SIGNATURES CONTRADICTOIRES
# ==========================================

print("\n--- SIGNATURES CONTRADICTOIRES ---")

# Regrouper les flux ayant les mêmes caractéristiques
grouped = df.groupby(features, dropna=False)["Label"]

# Compter le nombre d'étiquettes différentes
# pour chaque signature
label_counts = grouped.nunique()

# Identifier les signatures associées
# à plusieurs étiquettes
conflicting = label_counts[label_counts > 1]

print("Signatures uniques :", len(label_counts))
print("Signatures avec plusieurs étiquettes :", len(conflicting))

# Compter les flux concernés
if len(conflicting) > 0:
    conflict_rows = df.set_index(features).index.isin(
        conflicting.index
    )

    print("Flux concernés :", conflict_rows.sum())
    print(f"Pourcentage : {conflict_rows.mean() * 100:.2f}%")
else:
    print("Aucune signature contradictoire trouvée.")


# ==========================================
# LIMITE THÉORIQUE DES 6 CARACTÉRISTIQUES
# ==========================================

print("\n--- LIMITE THÉORIQUE DU DATASET ---")

# Compter les observations de chaque classe
# pour chaque signature
counts = df.groupby(features)["Label"].value_counts()

# Organiser les résultats en tableau
counts_table = counts.unstack(fill_value=0)

# Calculer le nombre minimal d'erreurs par signature
#formule utiliser :Erreurs minimales = total des Flux - Effectif de la classe majoritaire

minimum_errors = (
    counts_table.sum(axis=1)
    - counts_table.max(axis=1)
)

# Total des erreurs inévitables
total_minimum_errors = minimum_errors.sum()

# Taux d'erreur minimal
minimum_error_rate = total_minimum_errors / len(df)

# Accuracy maximale sur ces observations
maximum_accuracy = 1 - minimum_error_rate

print("Erreurs minimales :", total_minimum_errors)

print(
    f"Taux d'erreur minimal : "
    f"{minimum_error_rate * 100:.4f}%"
)

print(
    f"Accuracy maximale théorique : "
    f"{maximum_accuracy * 100:.4f}%"
)

# Sauvegarder le modèle supervisé
joblib.dump(
    {
        "model": model,
        "features": features,
        "classes": ["BENIGN", "PortScan"]
    },
    "models/random_forest_portscan.pkl"
)

print("Modèle Random Forest sauvegardé.")
