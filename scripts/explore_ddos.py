
import pandas as pd

# Charger le dataset DDoS
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(file_path)

# Nettoyer les noms des colonnes
df.columns = df.columns.str.strip()

print("--- DATASET DDOS ---")

print("Dimensions :", df.shape)

print("\nTypes de trafic :")
print(df["Label"].value_counts())

print("\nColonnes disponibles :")
print(df.columns.tolist())

import pandas as pd

# Charger le dataset DDoS
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(file_path)

# Nettoyer les noms des colonnes
df.columns = df.columns.str.strip()

print("--- DATASET DDOS ---")

print("Dimensions :", df.shape)

print("\nTypes de trafic :")
print(df["Label"].value_counts())

print("\nColonnes disponibles :")
print(df.columns.tolist())
