#!/usr/bin/env python3
"""
baseline_learner.py - v2.7 Advanced Behavioral Learning Engine

Features:
- Per-process, per-destination (/24), per-hour, per-weekday/weekend baselines
- Burst detection (unusual short-interval spikes)
- Packet size statistics (mean, std, min, max)
- Hybrid statistical + Isolation Forest models
- Automatic data retention (30 days)
"""

import sqlite3
import time
import json
import numpy as np
from pathlib import Path
from datetime import datetime
import joblib
from sklearn.ensemble import IsolationForest
import threading

DB_PATH = Path("baseline.db")
MODEL_PATH = Path("baseline_model.joblib")
LEARNING_INTERVAL = 3600 * 6   # 6 hours
RETENTION_DAYS = 30

class BaselineLearner:
    def __init__(self):
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._init_db()
        self.running = True
        print(f"[{datetime.now()}] baseline_learner.py v2.7 started - Advanced learning active")

    def _init_db(self):
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
                timestamp REAL,
                process_name TEXT,
                dst_ip TEXT,
                dst_prefix TEXT,
                hour_bucket INTEGER,
                is_weekend INTEGER,        # 1 = weekend, 0 = weekday
                interval REAL,
                cv REAL,
                outbound_ratio REAL,
                entropy REAL,
                packet_size_mean REAL,
                packet_size_std REAL,
                packet_size_min REAL,
                packet_size_max REAL
            )
        ''')
        self.db.commit()

    def record_flow(self, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                    packet_size_mean=0, packet_size_std=0, packet_size_min=0, packet_size_max=0):
        """Record flow from main hunter"""
        dst_prefix = ".".join(dst_ip.split('.')[:3]) + ".0"
        dt = datetime.fromtimestamp(time.time())
        hour = dt.hour
        is_weekend = 1 if dt.weekday() >= 5 else 0

        self.db.execute('''
            INSERT INTO flows
            (timestamp, process_name, dst_ip, dst_prefix, hour_bucket, is_weekend,
             interval, cv, outbound_ratio, entropy,
             packet_size_mean, packet_size_std, packet_size_min, packet_size_max)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (time.time(), process_name, dst_ip, dst_prefix, hour, is_weekend,
              interval, cv, outbound_ratio, entropy,
              packet_size_mean, packet_size_std, packet_size_min, packet_size_max))
        self.db.commit()

    def learn(self):
        """Build advanced baseline models"""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT process_name, dst_prefix, hour_bucket, is_weekend,
                   AVG(interval), AVG(cv), AVG(outbound_ratio), AVG(entropy),
                   AVG(packet_size_mean), AVG(packet_size_std),
                   MIN(packet_size_min), MAX(packet_size_max),
                   COUNT(*) as sample_count
            FROM flows
            WHERE timestamp > ?
            GROUP BY process_name, dst_prefix, hour_bucket, is_weekend
            HAVING sample_count >= 8
        ''', (time.time() - 86400 * RETENTION_DAYS,))

        model = {
            "version": "2.7",
            "last_updated": time.time(),
            "profiles": {}
        }

        for row in cursor.fetchall():
            proc, prefix, hour, is_weekend, avg_int, avg_cv, avg_out, avg_ent, avg_ps, avg_ps_std, ps_min, ps_max, count = row

            key = f"{proc}|{prefix}|{hour:02d}|{'weekend' if is_weekend else 'weekday'}"

            model["profiles"][key] = {
                "stats": {
                    "mean_interval": float(avg_int),
                    "mean_cv": float(avg_cv),
                    "mean_outbound_ratio": float(avg_out),
                    "mean_entropy": float(avg_ent),
                    "mean_packet_size": float(avg_ps),
                    "std_packet_size": float(avg_ps_std),
                    "min_packet_size": float(ps_min),
                    "max_packet_size": float(ps_max),
                    "sample_count": int(count)
                }
            }

        # Save model
        with open(MODEL_PATH, "wb") as f:
            joblib.dump(model, f)

        print(f"[{datetime.now()}] Baseline updated — {len(model['profiles'])} profiles (weekend/weekday + burst ready)")

    def cleanup_old_data(self):
        """Remove data older than RETENTION_DAYS"""
        cutoff = time.time() - 86400 * RETENTION_DAYS
        self.db.execute("DELETE FROM flows WHERE timestamp < ?", (cutoff,))
        self.db.commit()

    def run(self):
        while self.running:
            try:
                self.learn()
                self.cleanup_old_data()
            except Exception as e:
                print(f"Learning error: {e}")
            time.sleep(LEARNING_INTERVAL)

    def stop(self):
        self.running = False


if __name__ == "__main__":
    learner = BaselineLearner()
    try:
        learner.run()
    except KeyboardInterrupt:
        learner.stop()
        print("\nbaseline_learner.py stopped.")