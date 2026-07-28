# live_detection.py

from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from datasketch import MinHash, MinHashLSH


# ---------------- Config ----------------
TIME_WINDOWS = ['1-3h', '4-6h', '7-9h', '10-12h']
PACKETS_PER_SLOT = 250
ANOMALIES_PER_SLOT = 25


# ---------------- Feature Extraction ----------------
def extract_features(packet):
    try:
        return [
            len(packet),
            1 if TCP in packet else (2 if UDP in packet else 0),
            hash(packet[IP].src) % 1000 if IP in packet else 0,
            hash(packet[IP].dst) % 1000 if IP in packet else 0,
            getattr(packet, 'sport', 0),
            getattr(packet, 'dport', 0)
        ]
    except Exception:
        return None


def packet_handler(packet, features_list):
    features = extract_features(packet)
    if features is not None:
        features_list.append(features)


# ---------------- Anomaly Injection ----------------
def inject_anomalies(X, count=20):
    anomalies = np.random.normal(
        loc=20,
        scale=5,
        size=(count, X.shape[1])
    )

    y_true = np.array([0] * len(X) + [1] * count)

    X_full = np.vstack([X, anomalies])

    return X_full, y_true


# ---------------- Bayesian Detection ----------------
def bayesian_detect(X, y_true):
    n_normal = len(y_true) - np.sum(y_true)

    model = GaussianNB()

    model.fit(
        X[:n_normal],
        y_true[:n_normal]
    )

    y_pred = model.predict(X)

    return accuracy_score(y_true, y_pred)


# ---------------- LSH Detection ----------------
def lsh_detect(X, y_true):

    lsh = MinHashLSH(
        threshold=0.5,
        num_perm=64
    )

    n_normal = len(y_true) - np.sum(y_true)

    # Insert normal packets
    for i, row in enumerate(X[:n_normal]):
        m = MinHash(num_perm=64)

        for val in row:
            m.update(str(val).encode('utf8'))

        lsh.insert(f'item_{i}', m)

    predictions = []

    # Query packets
    for row in X:

        m = MinHash(num_perm=64)

        for val in row:
            m.update(str(val).encode('utf8'))

        similarity = len(lsh.query(m)) / max(1, n_normal)

        if similarity < 0.1:
            predictions.append(1)
        else:
            predictions.append(0)

    return accuracy_score(y_true, predictions)


# ---------------- Main Detection Function ----------------
def run_live_detection():

    all_results = []

    for slot in TIME_WINDOWS:

        features = []

        try:

            sniff(
                prn=lambda pkt: packet_handler(pkt, features),
                count=PACKETS_PER_SLOT,
                timeout=60,
                store=False
            )

        except Exception as e:

            all_results.append({
                'window': slot,
                'bayes_accuracy': 0.0,
                'lsh_accuracy': 0.0,
                'avg_data_volume': 0.0,
                'error': str(e)
            })

            continue

        # No packets captured
        if len(features) == 0:

            all_results.append({
                'window': slot,
                'bayes_accuracy': 0.0,
                'lsh_accuracy': 0.0,
                'avg_data_volume': 0.0
            })

            continue

        # Create dataframe
        df = pd.DataFrame(
            features,
            columns=[
                'length',
                'protocol',
                'src',
                'dst',
                'sport',
                'dport'
            ]
        )

        # Save packets
        df.to_csv('sniff_packets.csv', index=False)

        avg_data_volume = df['length'].mean()

        X, y_true = inject_anomalies(
            df.values,
            ANOMALIES_PER_SLOT
        )

        bayes_acc = bayesian_detect(
            X,
            y_true
        )

        lsh_acc = lsh_detect(
            X,
            y_true
        )

        all_results.append({
            'window': slot,
            'bayes_accuracy': round(
                bayes_acc * 100,
                2
            ),
            'lsh_accuracy': round(
                lsh_acc * 100,
                2
            ),
            'avg_data_volume': round(
                avg_data_volume,
                2
            )
        })

    return all_results