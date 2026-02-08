#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Configuration
LOG_FILE="/var/log/aide_config.log"
AIDE_CONF="/etc/aide/aide.conf"
AIDE_CONF_DIR="/etc/aide/aide.conf.d"
RSYSLOG_CONF="/etc/rsyslog.d/50-default.conf"
CHECKSUM="sha512"
EXCLUSIONS=(
  "!/var/lib/lxcfs/cgroup"
  "!/var/lib/docker"
)
VERBOSE=${VERBOSE:-"N"}
BACKUP_DIR="/var/backups/aide"
SCRIPT_COUNT=1

# Log function
log() {
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOG_FILE"
}

# Check dependencies
check_deps() {
  local deps=("aide" "aideinit" "systemctl" "rsyslogd")
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      log "Error: $cmd is not installed"
      exit 1
    fi
  done
}

# Check root or CAP_SYS_ADMIN
check_privileges() {
  if ! capsh --print | grep -q "cap_sys_admin"; then
    log "Error: This script requires root or CAP_SYS_ADMIN privileges"
    exit 1
  fi
}

# Backup file
backup_file() {
  local file=$1
  if [[ -f "$file" ]]; then
    local backup="$BACKUP_DIR/$(basename "$file").$(date +%s)"
    mkdir -p "$BACKUP_DIR"
    cp "$file" "$backup"
    log "Backed up $file to $backup"
  fi
}

# Configure cron and at
cron() {
  log "[$SCRIPT_COUNT] Configuring /etc/cron and /etc/at"

  # Remove deny files
  rm -f /etc/cron.deny /etc/at.deny 2>/dev/null

  # Restrict to root
  echo 'root' | tee /etc/cron.allow /etc/at.allow >/dev/null
  chown root:root /etc/cron* /etc/at*
  chmod 600 /etc/cron* /etc/at*

  # Disable atd
  systemctl mask atd.service >/dev/null 2>&1
  systemctl stop atd.service >/dev/null 2>&1
  systemctl daemon-reload

  # Enable cron logging
  if [[ -f "$RSYSLOG_CONF" ]]; then
    backup_file "$RSYSLOG_CONF"
    sed -i 's/^#cron\./cron\./' "$RSYSLOG_CONF"
  fi

  if [[ "$VERBOSE" == "Y" ]]; then
    systemctl status atd.service --no-pager || true
    echo
  fi

  ((SCRIPT_COUNT++))
}

# Configure AIDE
aide() {
  log "[$SCRIPT_COUNT] Configuring AIDE"

  # Create AIDE conf directory
  mkdir -p "$AIDE_CONF_DIR"
  chown root:root "$AIDE_CONF_DIR"
  chmod 750 "$AIDE_CONF_DIR"

  # Add exclusions
  for excl in "${EXCLUSIONS[@]}"; do
    local conf_file="$AIDE_CONF_DIR/70_aide_$(echo "$excl" | tr -d '/!' | tr '/' '_')"
    if ! grep -Fx "$excl" "$AIDE_CONF_DIR"/* 2>/dev/null; then
      echo "$excl" > "$conf_file"
      chown root:root "$conf_file"
      chmod 644 "$conf_file"
      log "Added exclusion $excl to $conf_file"
    fi
  done

  # Update checksum
  if [[ -f "$AIDE_CONF" ]]; then
    backup_file "$AIDE_CONF"
    if grep -q '^Checksums' "$AIDE_CONF"; then
      sed -i "s/^Checksums.*/Checksums = $CHECKSUM/" "$AIDE_CONF"
    else
      echo "Checksums = $CHECKSUM" >> "$AIDE_CONF"
    fi
    log "Set checksum to $CHECKSUM in $AIDE_CONF"
  else
    log "Error: $AIDE_CONF not found"
    exit 1
  fi

  ((SCRIPT_COUNT++))
}

# Initialize AIDE database
aide_post() {
  log "[$SCRIPT_COUNT] Initializing AIDE database (this may take a while)"

  if ! aideinit --yes; then
    log "Error: aideinit failed, check logs for details"
    exit 1
  fi

  ((SCRIPT_COUNT++))
}

# Setup AIDE timer
aide_timer() {
  log "[$SCRIPT_COUNT] Configuring daily AIDE check"

  local service_file="/etc/systemd/system/aidecheck.service"
  local timer_file="/etc/systemd/system/aidecheck.timer"

  # Create systemd service and timer if not present
  if [[ ! -f "$service_file" ]] || [[ ! -f "$timer_file" ]]; then
    # Write aidecheck.service
    cat << 'EOF' > "$service_file"
[Unit]
Description=AIDE daily check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
Nice=19
IOSchedulingClass=idle
EOF

    # Write aidecheck.timer
    cat << 'EOF' > "$timer_file"
[Unit]
Description=Daily AIDE check timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    chown root:root "$service_file" "$timer_file"
    chmod 644 "$service_file" "$timer_file"
    log "Created $service_file and $timer_file"
  fi

  systemctl daemon-reload
  systemctl enable aidecheck.timer >/dev/null
  systemctl restart aidecheck.timer >/dev/null

  if [[ "$VERBOSE" == "Y" ]]; then
    systemctl status aidecheck.timer --no-pager || true
    echo
  fi

  ((SCRIPT_COUNT++))
}

# Main
check_deps
check_privileges

# Initialize log file
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chown root:root "$LOG_FILE"
chmod 640 "$LOG_FILE"

log "Starting AIDE configuration"

aide
aide_post
aide_timer
cron

log "Configuration complete"
log "  AIDE config: $AIDE_CONF"
log "  Exclusions: $AIDE_CONF_DIR/70_aide_*"
log "  Log file: $LOG_FILE"
log "  Systemd timer: /etc/systemd/system/aidecheck.timer"