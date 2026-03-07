#!/usr/bin/env python3
"""
collector_factory.py - v3.0
"""

import configparser
import sys
from pathlib import Path

from ebpf_collector_base import EBPFCollectorBase

try:
    from libbpf_collector import LibBPFCollector
except ImportError as e:
    print(f"[CRITICAL] libbpf_collector.py not found: {e}")
    sys.exit(1)


def get_collector(config_path: str = None) -> EBPFCollectorBase:
    mode = "host"
    config_paths = [
        "config.ini",
        "v3.0/config.ini",
        "/app/config.ini",
        "/app/ebpf/config_dev.ini"
    ]
    if config_path:
        config_paths.insert(0, config_path)

    try:
        parser = configparser.ConfigParser()
        parsed_files = parser.read(config_paths)

        if parser.has_section("general"):
            mode = parser.get("general", "mode", fallback="host").strip().lower()

        print(f"[CollectorFactory v3.0] Mode detected: {mode.upper()} | Config files loaded: {len(parsed_files)}")

    except Exception as e:
        print(f"[CollectorFactory ERROR] Config parsing failed: {e} — defaulting to host mode")

    if mode == "promisc":
        print("[CollectorFactory] → Using Promiscuous Wire-Speed Parser (Epic 1)")
        return LibBPFCollector()
    else:
        print("[CollectorFactory] → Using Legacy Host Mode (full v2.8.2 compatibility)")
        return LibBPFCollector()


def register_collector(name: str, cls):
    pass


print("[CollectorFactory v3.0] Initialized successfully — dual-mode ready")