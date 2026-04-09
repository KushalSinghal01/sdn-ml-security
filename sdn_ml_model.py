import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import pickle
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("  SDN Security - ML Based Detection & Mitigation")
print("  Algorithm: Random Forest Classifier")
print("=" * 60)

# ─── STEP 1: Load Dataset ───
print("\n[1] Loading dataset...")
df = pd.read_csv('dataset_sdn.csv')
print(f"    Total samples  : {len(df)}")
print(f"    Total features : {len(df.columns) - 1}")
print(f"    Normal traffic : {len(df[df['label'] == 0])} samples")
print(f"    Attack traffic : {len(df[df['label'] == 1])} samples")

# ─── STEP 2: Preprocessing ───
print("\n[2] Preprocessing data...")

# Drop missing values
df = df.dropna()
print(f"    After removing nulls: {len(df)} samples")

# Encode categorical columns
le_src = LabelEncoder()
le_dst = LabelEncoder()
le_proto = LabelEncoder()

df['src'] = le_src.fit_transform(df['src'].astype(str))
df['dst'] = le_dst.fit_transform(df['dst'].astype(str))
df['Protocol'] = le_proto.fit_transform(df['Protocol'].astype(str))

print("    Encoded: src, dst, Protocol")

# ─── STEP 3: Feature Selection ───
print("\n[3] Selecting features...")

# Drop timestamp (not useful for prediction)
feature_cols = [col for col in df.columns if col not in ['label', 'dt']]
X = df[feature_cols]
y = df['label']

print(f"    Features used  : {len(feature_cols)}")
print(f"    Feature list   : {feature_cols}")

# ─── STEP 4: Train/Test Split ───
print("\n[4] Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"    Training set   : {len(X_train)} samples (80%)")
print(f"    Testing set    : {len(X_test)} samples (20%)")

# ─── STEP 5: Train Random Forest Model ───
print("\n[5] Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)
print("    Model trained successfully!")

# ─── STEP 6: Evaluate Model ───
print("\n[6] Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n    Accuracy       : {accuracy * 100:.2f}%")
print("\n    Classification Report:")
print(classification_report(y_test, y_pred,
      target_names=['Normal (0)', 'Attack (1)']))

print("    Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

# ─── STEP 7: Feature Importance ───
print("\n[7] Top 10 Most Important Features:")
importances = pd.Series(model.feature_importances_, index=feature_cols)
top_features = importances.nlargest(10)
for feat, imp in top_features.items():
    bar = '█' * int(imp * 100)
    print(f"    {feat:<15} {imp:.4f}  {bar}")

# ─── STEP 8: Save Model ───
print("\n[8] Saving model...")
with open('sdn_rf_model.pkl', 'wb') as f:
    pickle.dump({
        'model': model,
        'features': feature_cols,
        'le_src': le_src,
        'le_dst': le_dst,
        'le_proto': le_proto
    }, f)
print("    Model saved as: sdn_rf_model.pkl")

# ─── STEP 9: Mitigation Demo ───
print("\n[9] Mitigation Demo - Testing on sample traffic...")
print("-" * 50)

def detect_and_mitigate(traffic_sample, model_data):
    model = model_data['model']
    features = model_data['features']

    sample_df = pd.DataFrame([traffic_sample])

    # Encode categorical
    sample_df['src'] = model_data['le_src'].transform(
        [str(traffic_sample['src'])]
    ) if str(traffic_sample['src']) in model_data['le_src'].classes_ else [0]
    sample_df['dst'] = model_data['le_dst'].transform(
        [str(traffic_sample['dst'])]
    ) if str(traffic_sample['dst']) in model_data['le_dst'].classes_ else [0]
    sample_df['Protocol'] = model_data['le_proto'].transform(
        [str(traffic_sample['Protocol'])]
    ) if str(traffic_sample['Protocol']) in model_data['le_proto'].classes_ else [0]

    X_sample = sample_df[features]
    prediction = model.predict(X_sample)[0]
    confidence = model.predict_proba(X_sample)[0][prediction]

    return prediction, confidence

# Load saved model
with open('sdn_rf_model.pkl', 'rb') as f:
    model_data = pickle.load(f)

# Test samples
test_cases = [
    {
        'name': 'Normal HTTP traffic',
        'traffic': {
            'switch': 1, 'src': '10.0.0.1', 'dst': '10.0.0.2',
            'pktcount': 50, 'bytecount': 5000, 'dur': 10,
            'dur_nsec': 0, 'tot_dur': 10, 'flows': 2,
            'packetins': 5, 'pktperflow': 25, 'byteperflow': 2500,
            'pktrate': 5, 'Pairflow': 1, 'Protocol': 'TCP',
            'port_no': 80, 'tx_bytes': 5000, 'rx_bytes': 4000,
            'tx_kbps': 4, 'rx_kbps': 3, 'tot_kbps': 7
        }
    },
    {
        'name': 'SYN Flood Attack (DDoS)',
        'traffic': {
            'switch': 1, 'src': '10.0.0.1', 'dst': '10.0.0.8',
            'pktcount': 4777, 'bytecount': 5092282, 'dur': 10,
            'dur_nsec': 711000000, 'tot_dur': 10711000000.0, 'flows': 3,
            'packetins': 1790, 'pktperflow': 0, 'byteperflow': 0,
            'pktrate': 0, 'Pairflow': 0, 'Protocol': 'UDP',
            'port_no': 2, 'tx_bytes': 3753, 'rx_bytes': 1332,
            'tx_kbps': 0, 'rx_kbps': 0, 'tot_kbps': 0
        }
    }
]
for case in test_cases:
    pred, conf = detect_and_mitigate(case['traffic'], model_data)
    status = "ATTACK DETECTED" if pred == 1 else "NORMAL TRAFFIC"
    action = "BLOCKING attacker IP!" if pred == 1 else "Allowing traffic"
    src_ip = case['traffic']['src']

    print(f"\n  Traffic  : {case['name']}")
    print(f"  Source IP: {src_ip}")
    print(f"  Result   : {status} (confidence: {conf*100:.1f}%)")
    print(f"  Action   : {action}")
    if pred == 1:
        print(f"  POX Rule : ovs-ofctl add-flow s1 'nw_src={src_ip},actions=drop'")

print("\n" + "=" * 60)
print("  Detection + Mitigation Complete!")
print("=" * 60)
