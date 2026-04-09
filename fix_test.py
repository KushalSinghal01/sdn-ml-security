import pandas as pd
import pickle

df = pd.read_csv('dataset_sdn.csv')

print("Actual ATTACK sample from dataset:")
attack = df[df['label'] == 1].iloc[0]
print(attack)

print("\nActual NORMAL sample from dataset:")
normal = df[df['label'] == 0].iloc[0]
print(normal)
