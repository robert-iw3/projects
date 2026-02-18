"""
BeaconML.py
Advanced ML-based beaconing detection using K-Means clustering, Adaptive DBSCAN,
and Isolation Forest on time intervals.

Author: Robert Weber
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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    """
    Helper to compute silhouette score for a specific k.
    Run in parallel to find optimal cluster count.
    """
    if len(X) < k:
        return k, -1, None, None

    # Run K-Means
    kmeans = KMeans(n_clusters=k, random_state=0, n_init=10)
    labels = kmeans.fit_predict(X)

    # --- CRITICAL FIX ---
    # Scikit-learn throws an error if:
    # 1. Only 1 cluster is found (score undefined)
    # 2. Every sample is its own cluster (n_labels == n_samples)
    n_labels = len(np.unique(labels))
    n_samples = len(X)

    if 1 < n_labels < n_samples:
        try:
            score = silhouette_score(X, labels)
            return k, score, kmeans, labels
        except Exception:
            return k, -1, None, None

    return k, -1, None, None

def adaptive_eps_kdist(X, k_percent=5.0):
    """
    Calculates K-Distance elbow to find optimal EPS for DBSCAN.
    Uses the 90th percentile of k-distances as a heuristic.
    """
    if len(X) < 10:
        return 1.0 # Default fallback

    # Determine k based on percentage of data size
    n_neighbors = max(2, int(len(X) * k_percent / 100) + 1)

    # Calculate nearest neighbors
    neigh = NearestNeighbors(n_neighbors=n_neighbors)
    nbrs = neigh.fit(X)
    distances, _ = nbrs.kneighbors(X)

    # Sort distances to 5th nearest neighbor (or k-th)
    dist = np.sort(distances[:, -1])

    # Use 90th percentile as a robust estimator for the "knee"
    if len(dist) > 0:
        return float(np.percentile(dist, 90))
    return 1.0

def detect_beaconing_list(intervals, std_threshold=10.0, min_samples=3, use_dbscan=True, use_isolation=True, n_jobs=-1, max_samples=2000):
    """
    Main detection logic accepting a list of time intervals (deltas).
    Returns a string description of detected anomalies or None.
    """
    if not intervals or len(intervals) < min_samples:
        return None

    # Reshape for sklearn (n_samples, 1)
    X = np.array(intervals).reshape(-1, 1)

    # Subsample if data is massive (optimization)
    if len(X) > max_samples:
        np.random.seed(42)
        indices = np.random.choice(len(X), max_samples, replace=False)
        X_sub = X[indices]
    else:
        X_sub = X

    flags = []

    # --- 1. K-Means Clustering Analysis ---
    # Try k=2 to 5 to find periodic patterns
    max_k = min(5, len(X_sub) - 1)
    if max_k >= 2:
        results = Parallel(n_jobs=n_jobs)(
            delayed(compute_silhouette)(k, X_sub) for k in range(2, max_k + 1)
        )

        # Filter valid results and sort by score descending
        valid_results = [r for r in results if r[1] > -1]
        valid_results.sort(key=lambda x: x[1], reverse=True)

        if valid_results:
            best_k, best_score, best_model, best_labels = valid_results[0]

            # If silhouette score is high, structure exists
            if best_score > 0.6:
                # Check variance of the largest cluster
                unique, counts = np.unique(best_labels, return_counts=True)
                largest_cluster_label = unique[np.argmax(counts)]
                cluster_points = X_sub[best_labels == largest_cluster_label]
                std_dev = np.std(cluster_points)

                if std_dev < std_threshold:
                    flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {std_dev:.2f}, Score: {best_score:.2f})")

    # --- 2. Adaptive DBSCAN Analysis ---
    if use_dbscan:
        try:
            # Calculate dynamic epsilon
            eps = adaptive_eps_kdist(X_sub)
            # Ensure eps isn't too tiny for time intervals
            eps = max(eps, 0.5)

            db = DBSCAN(eps=eps, min_samples=min_samples).fit(X_sub)
            labels = db.labels_

            # Check core clusters (ignoring noise -1)
            unique_labels = set(labels)
            if -1 in unique_labels:
                unique_labels.remove(-1)

            for label in unique_labels:
                cluster_points = X_sub[labels == label]
                # If we find a tight cluster
                if len(cluster_points) >= min_samples:
                    std_dev = np.std(cluster_points)
                    if std_dev < std_threshold:
                        flags.append(f"ML Adaptive DBSCAN Beaconing (Core StdDev: {std_dev:.2f}, eps={eps:.3f})")
                        break # Found one, good enough
        except Exception:
            pass

    # --- 3. Isolation Forest (Outlier Detection) ---
    if use_isolation and len(X_sub) >= 10:
        iso = IsolationForest(contamination=0.1, random_state=42, n_jobs=n_jobs)
        anomalies = iso.fit_predict(X_sub)
        # -1 indicates anomaly
        anomaly_ratio = np.sum(anomalies == -1) / len(X_sub)

        # If anomalies are between 5% and 30%, it might be jittered beaconing + noise
        if 0.05 < anomaly_ratio < 0.40:
             flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {anomaly_ratio:.2f})")

    return '; '.join(flags) if flags else None

# Original file-based wrapper function
def detect_beaconing(intervals_file, std_threshold=10.0, min_samples=3, use_dbscan=True, use_isolation=True, n_jobs=-1, max_samples=2000):
    try:
        with open(intervals_file, 'r') as f:
            intervals = json.load(f)
    except Exception as e:
        return f"Error loading file: {str(e)}"
    return detect_beaconing_list(intervals, std_threshold, min_samples, use_dbscan, use_isolation, n_jobs, max_samples)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Beaconing Detection v2.3")
    parser.add_argument("intervals_file", help="Path to intervals JSON file")
    parser.add_argument("--std_threshold", type=float, default=10.0, help="StdDev threshold for tight clusters")
    parser.add_argument("--min_samples", type=int, default=3, help="Min samples for DBSCAN/Clusters")
    parser.add_argument("--use_dbscan", action="store_true", help="Enable DBSCAN")
    parser.add_argument("--use_isolation", action="store_true", help="Enable Isolation Forest")
    parser.add_argument("--n_jobs", type=int, default=-1, help="Parallel jobs (-1 for all cores)")

    args = parser.parse_args()

    result = detect_beaconing(
        args.intervals_file,
        args.std_threshold,
        args.min_samples,
        args.use_dbscan,
        args.use_isolation,
        args.n_jobs
    )

    if result:
        print(f"BEACON DETECTED: {result}")
    else:
        print("No beaconing detected.")