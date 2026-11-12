
import pandas as pd
import numpy as np
from pathlib import Path

file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"

df = pd.read_csv(file_path)

# Nettoyer les noms des colonnes
df.columns = df.columns.str.strip()

# Afficher les dimensions
print("Dimensions du dataset :", df.shape)

# Afficher les 5 premières lignes
print("\nPremières lignes :")
print(df.head())

# Afficher les colonnes disponibles
print("\nColonnes disponibles :")
print(df.columns.tolist())

# Compter les différents types de trafic
print("\nRépartition des types de trafic :")
print(df["Label"].value_counts())

# Sélectionner les caractéristiques à analyser
features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s"
]

# Afficher les statistiques descriptives
print("\nStatistiques des caractéristiques réseau :")
print(df[features].describe().to_string())


# Compter les valeurs manquantes
missing_values = df.isna().sum().sum()

# Sélectionner les colonnes numériques
numeric_data = df.select_dtypes(include="number")

# Compter les valeurs infinies
infinite_values = np.isinf(numeric_data).sum().sum()

# Compter les durées négatives
negative_durations = (df["Flow Duration"] < 0).sum()

print("\n--- QUALITÉ DES DONNÉES ---")
print("Valeurs manquantes :", missing_values)
print("Valeurs infinies :", infinite_values)
print("Durées négatives :", negative_durations)

# Remplacer les valeurs infinies par NaN
df = df.replace([np.inf, -np.inf], np.nan)

# Supprimer les lignes contenant des valeurs manquantes
df = df.dropna()

# Supprimer les flux avec une durée négative
df = df[df["Flow Duration"] >= 0]

# Afficher les résultats du nettoyage
print("\n--- APRÈS NETTOYAGE ---")
print("Dimensions :", df.shape)
print("Valeurs manquantes :", df.isna().sum().sum())
print("Valeurs infinies :", np.isinf(df.select_dtypes(include="number")).sum().sum())
print("Durées négatives :", (df["Flow Duration"] < 0).sum())


# Créer le dossier processed s'il n'existe pas
output_dir = Path("data/processed")
output_dir.mkdir(parents=True, exist_ok=True)

# Définir le chemin du fichier nettoyé
output_file = output_dir / "monday_clean.csv"

# Sauvegarder le DataFrame
df.to_csv(output_file, index=False)

print("\nDataset nettoyé sauvegardé :", output_file)