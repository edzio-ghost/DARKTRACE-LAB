
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

# Charger le dataset multiclasse
file_path = "data/processed/multiclass.csv"

df = pd.read_csv(file_path)

print("--- DATASET MULTICLASSE ---")
print("Dimensions :", df.shape)

print("\nRépartition des classes :")
print(df["Label"].value_counts())

# Sélectionner les caractéristiques
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow IAT Mean",
    "Flow Packets/s"
]

X = df[features]
y = df["Label"]

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

print("\n--- SÉPARATION PAR GROUPES ---")

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

# Définir l'ordre des classes
classes = ["BENIGN", "PortScan", "DDoS"]

print("\n--- MATRICE DE CONFUSION MULTICLASSE ---")

print(
    confusion_matrix(
        y_test,
        predictions,
        labels=classes
    )
)

print("\n--- RAPPORT DE CLASSIFICATION MULTICLASSE ---")

print(
    classification_report(
        y_test,
        predictions,
        labels=classes,
        digits=4,
        zero_division=0
    )
)

# Afficher l'importance des caractéristiques
print("\n--- IMPORTANCE DES CARACTÉRISTIQUES ---")

importances = pd.Series(
    model.feature_importances_,
    index=features
)

print(importances.sort_values(ascending=False))

# Sauvegarder le modèle supervisé
joblib.dump(
    {
        "model": model,
        "features": features,
        "classes": classes
    },
    "models/random_forest_multiclass.pkl"
)

print("\nModèle multiclasse sauvegardé.")

# ==========================================
# ANALYSE DES SIGNATURES MULTICLASSES
# ==========================================

print("\n--- SIGNATURES MULTICLASSES ---")

# Regrouper les flux ayant les mêmes caractéristiques
grouped = df.groupby(features)["Label"]

# Compter le nombre de classes par signature
label_counts = grouped.nunique()

# Identifier les signatures contradictoires
conflicting = label_counts[label_counts > 1]

print("Signatures uniques :", len(label_counts))
print("Signatures contradictoires :", len(conflicting))

# Compter les flux concernés
conflict_rows = df.set_index(features).index.isin(
    conflicting.index
)

print("Flux concernés :", conflict_rows.sum())

print(
    f"Pourcentage : "
    f"{conflict_rows.mean() * 100:.2f}%"
)

# ==========================================
# LIMITE THÉORIQUE MULTICLASSE
# ==========================================

print("\n--- LIMITE THÉORIQUE MULTICLASSE ---")

# Compter les classes pour chaque signature
counts = df.groupby(features)["Label"].value_counts()

counts_table = counts.unstack(fill_value=0)

# Calculer les erreurs minimales
minimum_errors = (
    counts_table.sum(axis=1)
    - counts_table.max(axis=1)
)

total_minimum_errors = minimum_errors.sum()

minimum_error_rate = total_minimum_errors / len(df)

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
