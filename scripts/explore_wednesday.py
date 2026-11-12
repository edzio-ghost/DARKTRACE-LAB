
import pandas as pd

# Charger le dataset du mercredi
file_path = "data/raw/MachineLearningCSV/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

print("--- DATASET DU MERCREDI ---")

print("Dimensions :", df.shape)

print("\nRépartition des classes :")
print(df["Label"].value_counts())

print("\nPourcentages :")
print(
    df["Label"].value_counts(normalize=True) * 100
)
