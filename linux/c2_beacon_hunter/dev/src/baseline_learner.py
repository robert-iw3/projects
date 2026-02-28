#!/usr/bin/env python3
"""
baseline_learner.py - v2.7 Advanced Behavioral Learning Engine

Features:
- Per-process, per-destination (/24), per-hour, per-weekday/weekend baselines
- Batch database inserts with timeout handling
- Hybrid statistical + Isolation Forest models (batch-fitted for large data)
- Automatic data retention (30 days)
- Model versioning
"""

import sqlite3
import time
import json
import numpy as np
from pathlib import Path
from collections import defaultdict
import threading
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib
import queue

DB_PATH = Path("baseline.db")
MODEL_PATH = Path("baseline_model.joblib")
LEARNING_INTERVAL = 3600 * 6
RETENTION_DAYS = 30
BATCH_SIZE = 100
QUEUE_TIMEOUT = 2.0
CHUNK_SIZE = 1000    # For batch Isolation Forest fitting

class BaselineLearner:
    def __init__(self):
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL;')
        self._init_db()
        self.flow_queue = queue.Queue()
        self.running = True

        self.writer_thread = threading.Thread(target=self._batch_writer, daemon=True)
        self.writer_thread.start()

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
                is_weekend INTEGER,
                interval REAL,
                cv REAL,
                outbound_ratio REAL,
                entropy REAL,
                packet_size_mean REAL,
                packet_size_std REAL,
                packet_size_min REAL,
                packet_size_max REAL,
                mitre_tactic TEXT
            )
        ''')
        self.db.commit()

    def record_flow(self, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                    packet_size_mean=0, packet_size_std=0, packet_size_min=0, packet_size_max=0,
                    mitre_tactic="C2_Beaconing"):
        dst_prefix = ".".join(dst_ip.split('.')[:3]) + ".0"
        dt = datetime.fromtimestamp(time.time())
        hour = dt.hour
        is_weekend = 1 if dt.weekday() >= 5 else 0

        flow_data = (time.time(), process_name, dst_ip, dst_prefix, hour, is_weekend,
                     interval, cv, outbound_ratio, entropy,
                     packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                     mitre_tactic)

        self.flow_queue.put(flow_data)

    def _batch_writer(self):
        batch = []
        while self.running:
            try:
                item = self.flow_queue.get(timeout=QUEUE_TIMEOUT)
                batch.append(item)

                if len(batch) >= BATCH_SIZE:
                    self._write_batch(batch)
                    batch = []
            except queue.Empty:
                if batch:
                    self._write_batch(batch)
                    batch = []
            except Exception as e:
                print(f"Batch writer error: {e}")

    def _write_batch(self, batch):
        try:
            self.db.executemany('''
                INSERT INTO flows
                (timestamp, process_name, dst_ip, dst_prefix, hour_bucket, is_weekend,
                 interval, cv, outbound_ratio, entropy,
                 packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                 mitre_tactic)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', batch)
            self.db.commit()
        except Exception as e:
            print(f"Batch insert error: {e}")

    def learn(self):
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

        training_data = []
        keys = []

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

            training_data.append([float(avg_int), float(avg_cv), float(avg_out), float(avg_ent), float(avg_ps)])

            keys.append(key)

        # Batch-fit Isolation Forest for large datasets
        if training_data:
            clf = IsolationForest(contamination=0.05, random_state=42)
            for i in range(0, len(training_data), CHUNK_SIZE):
                chunk = training_data[i:i+CHUNK_SIZE]
                clf.fit(chunk)
            model["isolation_forest"] = clf

        joblib.dump(model, MODEL_PATH)

        print(f"[{datetime.now()}] Baseline updated with {len(model['profiles'])} profiles")

    def cleanup_old_data(self):
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
        self.writer_thread.join(timeout=3)


if __name__ == "__main__":
    learner = BaselineLearner()
    try:
        learner.run()
    except KeyboardInterrupt:
        learner.stop()
        print("\n baseline_learner.py stopped.")