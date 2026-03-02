"""
BeaconML.py
Advanced ML-based beaconing detection using Multi-Dimensional Clustering.

Author: Robert Weber
Version: 2.8

This module acts as the core mathematical detection engine for identifying Command and Control (C2)
beaconing patterns in raw network traffic. It transitions from purely temporal analysis to a
multi-dimensional threat hunting approach by analyzing both the timing of network events and the
Shannon Entropy of their payloads.

Key Capabilities & Algorithms:
- Multi-Dimensional Feature Space: Dynamically evaluates 1D arrays (pure time intervals) or
  2D arrays (intervals + payload entropy) to detect mathematically perfect timing combined with
  highly obfuscated/encrypted payloads.
- StandardScaler Normalization: Equalizes the variance weight between raw seconds (intervals)
  and the 0.0-1.0 scale (entropy) before clustering, preventing temporal data from washing out
  payload analysis in Euclidean space.
- Optimized K-Means Clustering: Evaluates multiple 'k' values using silhouette scores to find
  the tightest, most robotic clusters of network traffic.
- Adaptive DBSCAN: Utilizes Nearest Neighbors to dynamically calculate the epsilon threshold,
  identifying dense behavioral clusters without relying on fixed parameters.
- Isolation Forest: Identifies statistical outliers and anomalous network behaviors that deviate
  from the micro-batch baseline.
- Lomb-Scargle Periodogram: Performs spectral frequency analysis to detect persistent periodicity
  and beaconing rhythms, even when the malware utilizes heavy temporal jitter to evade standard
  standard deviation checks.
"""

import sys
import json
import argparse
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
from joblib import Parallel, delayed
from astropy.timeseries import LombScargle
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def compute_silhouette(k, X):
    """Helper to compute silhouette score for a specific k."""
    if len(X) < k:
        return k, -1, None, None

    kmeans = KMeans(n_clusters=k, random_state=0, n_init=10)
    labels = kmeans.fit_predict(X)

    n_labels = len(np.unique(labels))
    n_samples = len(X)

    if 1 < n_labels < n_samples:
        score = silhouette_score(X, labels)
        return k, score, kmeans, labels
    return k, -1, None, None


def detect_beaconing_list(intervals, timestamps=None, payload_entropies=None, std_threshold=10.0,
                          min_samples=3, use_dbscan=True, use_isolation=True, n_jobs=-1, max_samples=2000):
    """
    Analyzes lists of intervals and optional payload entropies for C2 beaconing patterns.
    """
    if not intervals or len(intervals) < min_samples:
        return None

    # Truncate to max_samples for performance
    intervals = intervals[-max_samples:]
    if timestamps:
        timestamps = timestamps[-max_samples:]
    if payload_entropies:
        payload_entropies = payload_entropies[-max_samples:]

    flags = []

    # 1. Feature Preparation (1D Time-Series vs 2D Multi-Dimensional)
    is_multidimensional = payload_entropies and len(payload_entropies) == len(intervals)

    if is_multidimensional:
        # Combine intervals and entropy into a 2D feature space
        features = np.column_stack((intervals, payload_entropies))
        # Standardize features so interval variance doesn't wash out the 0.0-1.0 entropy scale
        scaler = StandardScaler()
        X = scaler.fit_transform(features)
    else:
        # Fallback to standard 1D interval clustering
        X = np.array(intervals).reshape(-1, 1)

    # 2. Optimized K-Means with Silhouette Analysis
    max_k = min(10, len(X) - 1)
    if max_k > 1:
        results = Parallel(n_jobs=n_jobs)(
            delayed(compute_silhouette)(k, X) for k in range(2, max_k + 1)
        )

        best_k, best_score, best_kmeans, best_labels = -1, -1, None, None
        for k, score, kmeans, labels in results:
            if score > best_score:
                best_score = score
                best_k = k
                best_kmeans = kmeans
                best_labels = labels

        if best_kmeans is not None and best_score > 0.5:
            # Check properties of the best clusters
            min_std = float('inf')
            high_entropy_cluster_found = False

            for i in range(best_k):
                cluster_indices = np.where(best_labels == i)[0]
                if len(cluster_indices) >= min_samples:
                    cluster_intervals = np.array(intervals)[cluster_indices]
                    cluster_std = np.std(cluster_intervals)
                    min_std = min(min_std, cluster_std)

                    # If multi-dimensional, check if this tight timing cluster is ALSO highly obfuscated
                    if is_multidimensional:
                        cluster_entropies = np.array(payload_entropies)[cluster_indices]
                        if np.mean(cluster_entropies) > 0.85 and cluster_std <= std_threshold:
                            high_entropy_cluster_found = True

            if min_std <= std_threshold:
                if high_entropy_cluster_found:
                    flags.append(f"ML 2D K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, High Entropy, Score: {best_score:.2f})")
                else:
                    flags.append(f"ML K-Means Beaconing (Clusters: {best_k}, Min StdDev: {min_std:.2f}, Score: {best_score:.2f})")

    # 3. Adaptive DBSCAN (Density-Based Spatial Clustering)
    if use_dbscan and len(X) >= min_samples:
        try:
            # Dynamically calculate epsilon based on nearest neighbor distances
            nn = NearestNeighbors(n_neighbors=min_samples)
            neighbors = nn.fit(X)
            distances, _ = neighbors.kneighbors(X)
            # Use the 90th percentile of the k-distance graph as a dynamic eps
            eps = np.percentile(distances[:, -1], 90)

            if eps > 0:
                dbscan = DBSCAN(eps=eps, min_samples=min_samples)
                labels = dbscan.fit_predict(X)
                unique_labels = set(labels)

                for label in unique_labels:
                    if label != -1:  # Ignore noise
                        cluster_indices = np.where(labels == label)[0]
                        if len(cluster_indices) >= min_samples:
                            cluster_intervals = np.array(intervals)[cluster_indices]
                            core_std = np.std(cluster_intervals)

                            if core_std <= std_threshold:
                                if is_multidimensional:
                                    cluster_entropies = np.array(payload_entropies)[cluster_indices]
                                    if np.mean(cluster_entropies) > 0.85:
                                        flags.append(f"ML 2D Adaptive DBSCAN (Core StdDev: {core_std:.2f}, High Entropy, eps={eps:.3f})")
                                        break

                                flags.append(f"ML Adaptive DBSCAN Beaconing (Core StdDev: {core_std:.2f}, eps={eps:.3f})")
                                break
        except Exception as e:
            logging.debug(f"DBSCAN error: {e}")

    # 4. Isolation Forest (Anomaly Detection)
    if use_isolation and len(X) >= min_samples:
        try:
            clf = IsolationForest(contamination=0.05, random_state=42)
            preds = clf.fit_predict(X)
            anomaly_ratio = np.sum(preds == -1) / len(preds)
            if anomaly_ratio > 0.05:
                flags.append(f"ML Isolation Beaconing (Anomaly Ratio: {anomaly_ratio:.2f})")
        except Exception as e:
            logging.debug(f"Isolation Forest error: {e}")

    # 5. Lomb-Scargle Periodogram (Jitter/Frequency Analysis)
    if timestamps and len(timestamps) >= min_samples:
        try:
            t = np.array(timestamps)
            # Center timestamps and subtract min to avoid floating point precision loss
            t = t - t[0]
            # Create a signal where events are 1s
            y = np.ones_like(t)

            frequency, power = LombScargle(t, y).autopower(minimum_frequency=1/3600, maximum_frequency=1/1)
            max_power = np.max(power)

            if max_power > 0.8:
                best_freq = frequency[np.argmax(power)]
                period = 1 / best_freq
                flags.append(f"ML Spectral Beaconing (Power: {max_power:.2f}, Period: {period:.1f}s)")
        except Exception as e:
            logging.debug(f"Lomb-Scargle error: {e}")

    return "; ".join(flags) if flags else None


def detect_beaconing(intervals_file, std_threshold=10.0, min_samples=3, use_dbscan=True,
                     use_isolation=True, n_jobs=-1, max_samples=2000):
    """File-based wrapper for testing."""
    try:
        with open(intervals_file, 'r') as f:
            intervals = json.load(f)
    except Exception as e:
        return f"Error loading file: {str(e)}"

    return detect_beaconing_list(intervals, None, None, std_threshold, min_samples, use_dbscan, use_isolation, n_jobs, max_samples)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Beaconing Detection v2.8 (Multi-Dimensional Draft)")
    parser.add_argument("intervals_file", help="Path to intervals JSON file")
    parser.add_argument("--std_threshold", type=float, default=10.0, help="StdDev threshold for tight clusters")
    parser.add_argument("--min_samples", type=int, default=3, help="Min samples for DBSCAN/Clusters")
    parser.add_argument("--use_dbscan", action="store_true", help="Enable DBSCAN")
    parser.add_argument("--use_isolation", action="store_true", help="Enable Isolation Forest")
    parser.add_argument("--n_jobs", type=int, default=-1, help="Parallel jobs (-1 for all cores)")

    args = parser.parse_args()
    result = detect_beaconing(args.intervals_file, args.std_threshold, args.min_samples,
                              args.use_dbscan, args.use_isolation, args.n_jobs)
    print(result)