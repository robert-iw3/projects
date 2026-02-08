import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

# Configuration
LOG_FILE = "/var/log/aide_config.log"
JSON_LOG_FILE = "/var/log/aide_config.json"
BACKUP_DIR = "/var/backups/aide"
AIDE_CONF = "/etc/aide/aide.conf"
AIDE_CONF_DIR = "/etc/aide/aide.conf.d"
RSYSLOG_CONF = "/etc/rsyslog.d/50-default.conf"
CHECKSUM = "sha512"
EXCLUSIONS = [
    "!/var/lib/lxcfs/cgroup",
    "!/var/lib/docker"
]
SYSTEMD_SERVICE = "/etc/systemd/system/aidecheck.service"
SYSTEMD_TIMER = "/etc/systemd/system/aidecheck.timer"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ],
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger(__name__)

def setup_json_logging():
    """Initialize JSON log file."""
    Path(JSON_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(JSON_LOG_FILE).touch()
    os.chown(JSON_LOG_FILE, 0, 0)
    os.chmod(JSON_LOG_FILE, 0o640)

def log_json(status: str, message: str):
    """Log to JSON file."""
    with open(JSON_LOG_FILE, "a") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": status, "message": message}, f)
        f.write("\n")

def check_privileges():
    """Check for root or CAP_SYS_ADMIN."""
    try:
        result = subprocess.run(["capsh", "--print"], capture_output=True, text=True, check=True)
        if "cap_sys_admin" not in result.stdout:
            logger.error("This script requires root or CAP_SYS_ADMIN privileges")
            log_json("ERROR", "Missing required privileges")
            exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check capabilities: {e}")
        log_json("ERROR", f"Failed to check capabilities: {e}")
        exit(1)

def check_deps():
    """Check for required dependencies."""
    deps = ["aide", "aideinit", "systemctl", "rsyslogd"]
    for cmd in deps:
        if not shutil.which(cmd):
            logger.error(f"{cmd} is required but not installed")
            log_json("ERROR", f"{cmd} not installed")
            exit(1)

def backup_file(file: str):
    """Backup a file before modification."""
    file_path = Path(file)
    if file_path.exists():
        backup_path = Path(BACKUP_DIR) / f"{file_path.name}.{int(time.time())}"
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, backup_path)
        logger.info(f"Backed up {file} to {backup_path}")
        log_json("INFO", f"Backed up {file} to {backup_path}")

def configure_cron():
    """Configure cron and at restrictions."""
    logger.info("[1] Configuring /etc/cron and /etc/at")
    log_json("INFO", "Configuring cron and at")

    # Remove deny files
    for deny_file in ["/etc/cron.deny", "/etc/at.deny"]:
        deny_path = Path(deny_file)
        if deny_path.exists():
            deny_path.unlink()

    # Restrict to root
    for allow_file in ["/etc/cron.allow", "/etc/at.allow"]:
        with open(allow_file, "w") as f:
            f.write("root\n")
        os.chown(allow_file, 0, 0)
        os.chmod(allow_file, 0o600)

    # Set permissions
    for pattern in ["/etc/cron*", "/etc/at*"]:
        for path in Path("/etc").glob(pattern):
            os.chown(path, 0, 0)
            os.chmod(path, 0o600)

    # Disable atd
    subprocess.run(["systemctl", "mask", "atd.service"], check=True, capture_output=True)
    subprocess.run(["systemctl", "stop", "atd.service"], check=True, capture_output=True, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)

    # Enable cron logging
    if Path(RSYSLOG_CONF).exists():
        backup_file(RSYSLOG_CONF)
        with open(RSYSLOG_CONF, "r") as f:
            content = f.read()
        content = content.replace("#cron.", "cron.")
        with open(RSYSLOG_CONF, "w") as f:
            f.write(content)
        logger.info("Enabled cron logging in rsyslog")
        log_json("INFO", "Enabled cron logging in rsyslog")

def configure_aide():
    """Configure AIDE exclusions and checksum."""
    logger.info("[2] Configuring AIDE")
    log_json("INFO", "Configuring AIDE")

    Path(AIDE_CONF_DIR).mkdir(parents=True, exist_ok=True)
    os.chown(AIDE_CONF_DIR, 0, 0)
    os.chmod(AIDE_CONF_DIR, 0o750)

    # Add exclusions
    for excl in EXCLUSIONS:
        conf_file = Path(AIDE_CONF_DIR) / f"70_aide_{excl.replace('/', '_').replace('!', '')}"
        found = any(excl in p.read_text() for p in Path(AIDE_CONF_DIR).glob("*") if p.is_file())
        if not found:
            with open(conf_file, "w") as f:
                f.write(f"{excl}\n")
            os.chown(conf_file, 0, 0)
            os.chmod(conf_file, 0o644)
            logger.info(f"Added exclusion {excl} to {conf_file}")
            log_json("INFO", f"Added exclusion {excl} to {conf_file}")

    # Update checksum
    if Path(AIDE_CONF).exists():
        backup_file(AIDE_CONF)
        with open(AIDE_CONF, "r") as f:
            content = f.read()
        if "Checksums" in content:
            content = content.replace(r"Checksums.*", f"Checksums = {CHECKSUM}")
        else:
            content += f"\nChecksums = {CHECKSUM}\n"
        with open(AIDE_CONF, "w") as f:
            f.write(content)
        logger.info(f"Set checksum to {CHECKSUM} in {AIDE_CONF}")
        log_json("INFO", f"Set checksum to {CHECKSUM} in {AIDE_CONF}")
    else:
        logger.error(f"{AIDE_CONF} not found")
        log_json("ERROR", f"{AIDE_CONF} not found")
        exit(1)

def aide_post():
    """Initialize AIDE database."""
    logger.info("[3] Initializing AIDE database (this may take a while)")
    log_json("INFO", "Initializing AIDE database")
    try:
        subprocess.run(["aideinit", "--yes"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"aideinit failed: {e}")
        log_json("ERROR", f"aideinit failed: {e}")
        exit(1)

def aide_timer():
    """Setup AIDE daily check timer."""
    logger.info("[4] Configuring daily AIDE check")
    log_json("INFO", "Configuring daily AIDE check")

    service_content = """\
[Unit]
Description=AIDE daily check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
Nice=19
IOSchedulingClass=idle
"""
    timer_content = """\
[Unit]
Description=Daily AIDE check timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
"""
    for path, content in [(SYSTEMD_SERVICE, service_content), (SYSTEMD_TIMER, timer_content)]:
        if not Path(path).exists():
            with open(path, "w") as f:
                f.write(content)
            os.chown(path, 0, 0)
            os.chmod(path, 0o644)
            logger.info(f"Created {path}")
            log_json("INFO", f"Created {path}")

    subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
    subprocess.run(["systemctl", "enable", "aidecheck.timer"], check=True, capture_output=True)
    subprocess.run(["systemctl", "restart", "aidecheck.timer"], check=True, capture_output=True)

def main():
    parser = argparse.ArgumentParser(description="Configure AIDE for Linux")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument("--json", "-j", action="store_true", help="Output logs in JSON format")
    args = parser.parse_args()

    # Initialize logging
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(LOG_FILE).touch()
    os.chown(LOG_FILE, 0, 0)
    os.chmod(LOG_FILE, 0o640)
    if args.json:
        setup_json_logging()

    logger.info("Starting AIDE configuration")
    log_json("INFO", "Starting AIDE configuration")

    check_deps()
    check_privileges()
    configure_cron()
    configure_aide()
    aide_post()
    aide_timer()

    logger.info("Configuration complete")
    logger.info(f"  AIDE config: {AIDE_CONF}")
    logger.info(f"  Exclusions: {AIDE_CONF_DIR}/70_aide_*")
    logger.info(f"  Log file: {LOG_FILE}")
    logger.info(f"  Systemd timer: {SYSTEMD_TIMER}")
    log_json("INFO", "Configuration complete")

if __name__ == "__main__":
    main()