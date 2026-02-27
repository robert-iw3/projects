#!/usr/bin/env python3
"""
ebpf_collector_base.py - Abstract base class for eBPF collectors
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

    def record_flow(self, process_name, dst_ip, interval=0, cv=0, outbound_ratio=0,
                    entropy=0, packet_size_mean=0, packet_size_std=0):
        """Safe callback to baseline learner with error handling"""
        try:
            self.learner.record_flow(
                process_name=process_name,
                dst_ip=dst_ip,
                interval=interval,
                cv=cv,
                outbound_ratio=outbound_ratio,
                entropy=entropy,
                packet_size_mean=packet_size_mean,
                packet_size_std=packet_size_std
            )
        except Exception as e:
            print(f"Warning: Failed to record flow to learner: {e}")