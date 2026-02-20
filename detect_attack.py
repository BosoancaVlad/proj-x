import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

print("Loading log data...")
data = pd.read_csv('simulation_logs.csv')
data['timestamp'] = pd.to_datetime(data['timestamp'])

#group data by ip address and count failed attempts
features = data[data['status'] == 'failed'].groupby('ip_address').size().reset_index(name='fail_count')

print("\n--- Extracted Features ---")
print(features)

#ml model, isolation forest
model = IsolationForest(contamination=0.1, random_state=42)

#looks at fail_count and learns that is normal
model.fit(features[['fail_count']])

#predict attacks
features['anomaly'] = model.predict(features[['fail_count']])

print("\n--- ML Detection Results ---")
attacks = features[features['anomaly'] == -1]

if not attacks.empty:
    print("ALARM! The following IPs were detected as ATTACKERS by the AI:")
    for index, row in attacks.iterrows():
        print(f" -> IP: {row['ip_address']} with {row['fail_count']} failed attempts.")
else:
    print("No anomalies detected.")