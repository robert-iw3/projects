#!/usr/bin/env python3
"""
ebpf_collector_base.py - Abstract base class for eBPF collectors v2.7
"""

from abc import ABC, abstractmethod
from baseline_learner import BaselineLearner

class EBPFCollectorBase(ABC):
    def __init__(self):
        self.learner = BaselineLearner()
        self.running = False

    @abstractmethod
    def load_probes(self):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def stop(self):
        pass

    def record_flow(self, process_name, dst_ip, interval=0.0, cv=0.0, outbound_ratio=0.0,
                    entropy=0.0, packet_size_mean=0, packet_size_std=0,
                    packet_size_min=0, packet_size_max=0, mitre_tactic="C2_Beaconing"):
        """Safe callback to baseline learner with full metric and MITRE support"""
        try:
            self.learner.record_flow(
                process_name=process_name,
                dst_ip=dst_ip,
                interval=interval,
                cv=cv,
                outbound_ratio=outbound_ratio,
                entropy=entropy,
                packet_size_mean=packet_size_mean,
                packet_size_std=packet_size_std,
                packet_size_min=packet_size_min,
                packet_size_max=packet_size_max,
                mitre_tactic=mitre_tactic
            )
        except Exception as e:
            print(f"Warning: Failed to record flow to learner: {e}")