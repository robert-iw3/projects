#!/usr/bin/env python3
"""
collector_factory.py - Backend selector (BCC or libbpf)
"""

import configparser
from pathlib import Path

class CollectorFactory:
    @staticmethod
    def create_collector():
        config = configparser.ConfigParser()
        config.read('../config_dev.ini')

        backend = config.get('ebpf', 'backend', fallback='auto').lower()

        if backend == "libbpf":
            try:
                from libbpf_collector import LibBPFCollector
                print("Using libbpf + CO-RE backend (production mode)")
                return LibBPFCollector()
            except Exception as e:
                print(f"libbpf failed to load: {e}. Falling back to BCC.")
                from bcc_collector import BCCCollector
                return BCCCollector()
        else:
            from bcc_collector import BCCCollector
            print("Using BCC backend (development mode)")
            return BCCCollector()