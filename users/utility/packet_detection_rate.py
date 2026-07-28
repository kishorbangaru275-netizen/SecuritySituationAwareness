import numpy as np
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from datasketch import MinHash, MinHashLSH

# Configuration
TIME_WINDOWS = ['1-3h', '4-6h', '7-9h', '10-12h']
ANOMALIES_PER_SLOT = 25


# -------------------------------
# Anomaly Injection
# -------------------------------
def inject_anomalies(X, count=20):
    anomalies = np.random.normal(
        loc=20,
        scale=5,
        size=(count, X.shape[1])
    )

    y_true = np.array([0] * len(X) + [1] * count)
    X_full = np.vstack([X, anomalies])

    return X_full, y_true


# -------------------------------
# Bayesian Detection
# -------------------------------
def bayesian_detect(X, y_true):
    n_normal = len(y_true) - np.sum(y_true)

    model = GaussianNB()

    # Train using only normal samples
    model.fit(X[:n_normal], y_true[:n_normal])

    y_pred = model.predict(X)

    return accuracy_score(y_true, y_pred)


# -------------------------------
# LSH Detection
# -------------------------------
def lsh_detect(X, y_true):
    lsh = MinHashLSH(threshold=0.5, num_perm=64)

    n_normal = len(y_true) - np.sum(y_true)

    # Insert normal packets
    for i, row in enumerate(X[:n_normal]):
        m = MinHash(num_perm=64)

        for val in row:
            m.update(str(val).encode('utf8'))

        lsh.insert(f"item_{i}", m)

    predictions = []

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


# -------------------------------
# Main function
# -------------------------------
def run_detection_from_csv(csv_path):
    results = []

    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        return {
            "error": f"CSV file not found: {csv_path}"
        }
    except Exception as e:
        return {
            "error": str(e)
        }

    # Ensure CSV is not empty
    if df.empty:
        return {
            "error": "CSV file contains no data."
        }

    # Split dataframe into time windows
    chunks = np.array_split(df, len(TIME_WINDOWS))

    for i, chunk in enumerate(chunks):

        # Convert numpy array back to dataframe
        chunk = pd.DataFrame(chunk, columns=df.columns)

        if len(chunk) == 0:
            results.append({
                'slot': TIME_WINDOWS[i],
                'Bayes': 0.0,
                'LSH': 0.0,
                'AvgDataVolume': 0.0
            })
            continue

        try:
            # Calculate average packet size
            if 'length' in chunk.columns:
                avg_data_volume = chunk['length'].mean()
            else:
                avg_data_volume = 0

            # Convert dataframe to numpy array
            X_normal = chunk.values

            # Inject anomalies
            X, y_true = inject_anomalies(
                X_normal,
                ANOMALIES_PER_SLOT
            )

            # Detection accuracy
            bayes_acc = bayesian_detect(X, y_true)
            lsh_acc = lsh_detect(X, y_true)

            results.append({
                'slot': TIME_WINDOWS[i],
                'Bayes': round(bayes_acc * 100, 2),
                'LSH': round(lsh_acc * 100, 2),
                'AvgDataVolume': round(avg_data_volume, 2)
            })

        except Exception as e:
            results.append({
                'slot': TIME_WINDOWS[i],
                'Bayes': 0.0,
                'LSH': 0.0,
                'AvgDataVolume': 0.0,
                'error': str(e)
            })

    return results