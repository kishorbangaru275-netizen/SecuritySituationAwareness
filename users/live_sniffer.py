# users/live_sniffer.py

from scapy.all import sniff, IP, TCP, UDP
import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from datasketch import MinHash, MinHashLSH

def extract_features(packet):
    return [
        len(packet),
        1 if TCP in packet else (2 if UDP in packet else 0),
        hash(packet[IP].src) % 1000 if IP in packet else 0,
        hash(packet[IP].dst) % 1000 if IP in packet else 0,
        packet.sport if hasattr(packet, 'sport') else 0,
        packet.dport if hasattr(packet, 'dport') else 0
    ]

def inject_anomalies(X, count=20):
    anomalies = np.random.normal(20, 5, (count, X.shape[1]))
    y_true = np.array([0] * len(X) + [1] * count)
    X_full = np.vstack([X, anomalies])
    return X_full, y_true

def bayesian_detect(X, y_true):
    n_normal = len(y_true) - sum(y_true)
    model = GaussianNB()
    model.fit(X[:n_normal], y_true[:n_normal])
    y_pred = model.predict(X)
    return accuracy_score(y_true, y_pred)

def lsh_detect(X, y_true):
    lsh = MinHashLSH(threshold=0.5, num_perm=64)
    n_normal = len(y_true) - sum(y_true)

    for i, row in enumerate(X[:n_normal]):
        m = MinHash(num_perm=64)
        for val in row:
            m.update(str(val).encode('utf8'))
        lsh.insert(f"item_{i}", m)

    results = []
    for row in X:
        m = MinHash(num_perm=64)
        for val in row:
            m.update(str(val).encode('utf8'))
        sim = len(lsh.query(m)) / max(1, len(X))
        results.append(1 if sim < 0.1 else 0)
    return accuracy_score(y_true, results)

def packet_stream(callback_limit=250):
    features = []

    def handler(packet):
        try:
            features.append(extract_features(packet))
            if len(features) >= callback_limit:
                X = np.array(features)
                X, y_true = inject_anomalies(X)
                bayes_acc = bayesian_detect(X, y_true)
                lsh_acc = lsh_detect(X, y_true)
                avg_len = X[:, 0].mean()

                yield {
                    'bayesian': round(bayes_acc * 100, 2),
                    'lsh': round(lsh_acc * 100, 2),
                    'avg_len': round(avg_len, 2)
                }
                features.clear()
        except Exception:
            pass

    sniff(prn=handler, store=0)
