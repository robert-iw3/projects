"""
Docstring for windows.pwsh.c2_channel_detection.v2_ML_Algorithms.BeaconML
A simple ML-based beaconing detection using K-Means clustering on time intervals.
Performs Spectral Analysis (Lomb-Scargle) and Clustering (DBSCAN)
on network intervals to detect Jittered Beacons.

Author: Robert Weber

Usage:
python BeaconML.py <intervals_file.json> [--std_threshold 10.0] [--min_samples 3] [--use_dbscan] [--use_isolation] [--n_jobs -1] [--max_samples 1000]

Before Running:
pip install scikit-learn numpy joblib scipy
"""

import sys
import json
import argparse
import numpy as np
import logging
from scipy.signal import lombscargle
from sklearn.cluster import DBSCAN
from joblib import Parallel, delayed

# Configure Logging to Stderr (so Stdout stays clean for JSON)
logging.basicConfig(stream=sys.stderr, level=logging.ERROR)

def analyze_host(target, timestamps, config):
    """
    Analyzes a single host's timestamps for C2 patterns.
    Returns: (target, alert_string_or_None)
    """
    try:
        if len(timestamps) < config['min_samples']:
            return target, None

        # Sort and calculate deltas (intervals)
        timestamps = np.array(timestamps)
        timestamps.sort()
        intervals = np.diff(timestamps)

        # --- CHECK 1: STATISTICAL VARIANCE (Fastest) ---
        # Detects perfect, machine-like beacons (Cobalt Strike default)
        std_dev = np.std(intervals)
        if std_dev < config['std_threshold']:
            return target, f"Low Variance Beacon (StdDev: {std_dev:.4f}s)"

        # --- CHECK 2: SPECTRAL ANALYSIS (Lomb-Scargle) ---
        # Detects periodic beacons hidden by Jitter (High Variance)
        # We simulate a signal where Y is constant (1) at every timestamp X
        # Strong periodicity results in a high power peak at specific frequencies.

        # Frequencies to test: 0.01Hz (100s) to 1.0Hz (1s)
        freqs = np.linspace(0.01, 1.0, 100)

        # Scipy Lomb-Scargle expects: x (times), y (measurements), freqs
        # We treat every connection as a "signal pulse" of amplitude 1
        y = np.ones_like(timestamps)

        # angular frequencies for scipy
        w = 2 * np.pi * freqs
        pgram = lombscargle(timestamps, y, w, normalize=True)
        max_power = np.max(pgram)

        if max_power > 0.85: # 0.85 is a strong statistical confidence of periodicity
            return target, f"High Spectral Density (Periodicity Power: {max_power:.2f})"

        # --- CHECK 3: DBSCAN CLUSTERING ---
        # Detects "Modal" Beaconing (e.g., 90% of traffic is 5s, 10% is noise)
        if config['use_dbscan']:
            X = intervals.reshape(-1, 1)
            # Epsilon = allows for X seconds of jitter deviation
            jitter_tolerance = max(0.5, std_dev * 0.2)

            db = DBSCAN(eps=jitter_tolerance, min_samples=int(len(X)*0.4)).fit(X)
            labels = db.labels_

            # Count clusters (ignoring -1 noise)
            unique_labels = set(labels)
            if -1 in unique_labels: unique_labels.remove(-1)

            if len(unique_labels) >= 1:
                # Calculate size of the largest cluster
                main_cluster_ratio = np.sum(labels == list(unique_labels)[0]) / len(labels)
                if main_cluster_ratio > 0.6: # If 60% of traffic fits a tight pattern
                    return target, f"Cluster Beacon (Mode Found via DBSCAN)"

        return target, None

    except Exception as e:
        # Fail gracefully for single host
        return target, None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("batch_file", help="Path to JSON batch file")
    parser.add_argument("--std_threshold", type=float, default=2.0)
    parser.add_argument("--min_samples", type=int, default=5)
    parser.add_argument("--use_dbscan", action="store_true")
    parser.add_argument("--n_jobs", type=int, default=-1)
    args = parser.parse_args()

    try:
        with open(args.batch_file, 'r') as f:
            data = json.load(f)

        # Execute Parallel Analysis
        results = Parallel(n_jobs=args.n_jobs)(
            delayed(analyze_host)(target, ts, vars(args))
            for target, ts in data.items()
        )

        # Filter Nones and Create Result Dict
        alerts = {target: alert for target, alert in results if alert is not None}

        print(json.dumps(alerts))

    except Exception as e:
        # Output error as JSON so PowerShell can log it
        print(json.dumps({"error": str(e)}))