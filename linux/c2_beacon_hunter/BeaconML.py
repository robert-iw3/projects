"""
A simple ML-based beaconing detection using K-Means clustering on time intervals.
Author: Robert Weber

Added DBSCAN, Isolation Forest, subsampling, parallel silhouette.
"""

import sys
import json
import argparse
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors
from joblib import Parallel, delayed
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    if len(X) < k:
        return k, -1, None, None
    kmeans = KMeans(n_clusters=k, random_state=0, n_init=1)
    labels = kmeans.fit_predict(X)
    if len(np.unique(labels)) > 1:
        score = silhouette_score(X, labels)
        return k, score, kmeans, labels
    return k, -1, None, None

def adaptive_eps_kdist(X, k_percent=5.0):
    """k-distance elbow for adaptive DBSCAN eps"""
    if len(X) < 10:
        return 1.0
    n_neighbors = max(2, int(len(X) * k_percent / 100) + 1)
    neigh = NearestNeighbors(n_neighbors=n_neighbors)
    nbrs = neigh.fit(X)
    distances, _ = nbrs.kneighbors(X)
    dist = np.sort(distances[:, -1])
    if len(dist) > 10:
        diffs = np.diff(dist)
        knee = np.argmax(diffs) + 1
        eps = dist[knee]
    else:
        eps = np.percentile(dist, 90)
    return max(float(eps), 0.1)

def detect_beaconing_list(intervals, std_threshold=10.0, min_samples=3, use_dbscan=False, use_isolation=False, n_jobs=-1, max_samples=1000):
    if len(intervals) < min_samples:
        return "No Beaconing (Insufficient Data)"

    if len(intervals) > max_samples:
        logging.info(f"Subsampling from {len(intervals)} to {max_samples}")
        intervals = np.random.choice(intervals, max_samples, replace=False).tolist()

    X = np.array(intervals, dtype=np.float32).reshape(-1, 1)
    flags = []

    # K-Means
    max_k = min(5, len(X) + 1)
    results = Parallel(n_jobs=n_jobs)(
        delayed(compute_silhouette)(k, X) for k in range(2, max_k)
    )
    valid_results = [r for r in results if r[1] > -1]
    if valid_results:
        best_k, best_score, _, best_labels = max(valid_results, key=lambda x: x[1])
        cluster_std = [np.std(X[best_labels == i]) for i in np.unique(best_labels)]
        min_std = min(cluster_std)
        if min_std < std_threshold:
            flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, Score: {best_score:.2f})")

    # Adaptive DBSCAN
    if use_dbscan and len(X) >= min_samples:
        eps = adaptive_eps_kdist(X)
        dbscan = DBSCAN(eps=eps, min_samples=min_samples)
        labels = dbscan.fit_predict(X)
        core_std = np.std(X[labels != -1]) if np.any(labels != -1) else float('inf')
        if core_std < std_threshold:
            flags.append(f"ML Adaptive DBSCAN Beaconing (Core StdDev: {core_std:.2f}, eps={eps:.3f})")

    # Isolation Forest
    if use_isolation:
        subsample_size = min(256, len(X))
        X_sub = X[np.random.choice(len(X), subsample_size, replace=False)] if len(X) > subsample_size else X
        iso = IsolationForest(contamination=0.1, random_state=0, max_samples=subsample_size)
        anomalies = iso.fit_predict(X_sub)
        anomaly_ratio = np.sum(anomalies == -1) / len(X_sub)
        if anomaly_ratio > 0.05:
            flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {anomaly_ratio:.2f})")

    return '; '.join(flags) if flags else "No ML Beaconing"

# Original file-based function (unchanged)
def detect_beaconing(intervals_file, std_threshold=10.0, min_samples=3, use_dbscan=False, use_isolation=False, n_jobs=-1, max_samples=1000):
    try:
        with open(intervals_file, 'r') as f:
            intervals = json.load(f)
    except Exception as e:
        return f"Error loading file: {str(e)}"
    return detect_beaconing_list(intervals, std_threshold, min_samples, use_dbscan, use_isolation, n_jobs, max_samples)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Beaconing Detection v2.2")
    parser.add_argument("intervals_file", help="Path to intervals JSON")
    parser.add_argument("--std_threshold", type=float, default=10.0)
    parser.add_argument("--min_samples", type=int, default=3)
    parser.add_argument("--use_dbscan", action="store_true")
    parser.add_argument("--use_isolation", action="store_true")
    parser.add_argument("--n_jobs", type=int, default=-1)
    parser.add_argument("--max_samples", type=int, default=1000)
    args = parser.parse_args()
    result = detect_beaconing(args.intervals_file, args.std_threshold, args.min_samples, args.use_dbscan, args.use_isolation, args.n_jobs, args.max_samples)
    print(result)