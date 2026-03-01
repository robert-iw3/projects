#!/bin/bash

# ======================================================================================
# Script Name: threat_intel_check.sh
# Description: Automates external Threat Intelligence (CTI) enrichment for suspicious
#              IP addresses identified by the ML detection pipeline.
# Operations Performed:
#   1. Parses config.ini to retrieve API keys securely.
#   2. Reads the anomalies JSONL log to extract all unique, non-local destination
#      IPs associated with a high anomaly score (>= 80).
#   3. Queries multiple external APIs (VirusTotal, AlienVault OTX, GreyNoise,
#      AbuseIPDB, and Shodan) to gather reputation, campaign association, and
#      infrastructure profiling data.
#   4. Outputs a consolidated, human-readable text report containing the findings.
# Note:        Includes deliberate sleep intervals to avoid rate-limiting on
#              free-tier community API accounts.
# ======================================================================================

CONFIG_FILE="config.ini"

# Helper function to extract API keys from config.ini safely
get_config() {
    grep "^$1=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r' 2>/dev/null
}

LOG_FILE=$(get_config "LOG_FILE")
LOG_FILE=${LOG_FILE:-"../output/anomalies.jsonl"}
OUTPUT_DIR=$(get_config "OUTPUT_DIR")
OUTPUT_DIR=${OUTPUT_DIR:-"../output/"}
REPORT_OUT="${OUTPUT_DIR}threat_intel_report_$(date +%Y%m%d_%H%M%S).txt"

# Load API Keys
VT_API_KEY=$(get_config "VIRUSTOTAL_KEY")
OTX_API_KEY=$(get_config "ALIENVAULT_OTX_KEY")
GN_API_KEY=$(get_config "GREYNOISE_KEY")
ABUSEIPDB_KEY=$(get_config "ABUSEIPDB_KEY")
SHODAN_KEY=$(get_config "SHODAN_KEY")

if [ ! -f "$LOG_FILE" ]; then
    echo "[!] Error: Cannot find log file at $LOG_FILE"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
SUSPICIOUS_IPS=$(jq -r 'select(.score >= 80 and .dst_ip != "0.0.0.0") | .dst_ip' "$LOG_FILE" | sort -u)

if [ -z "$SUSPICIOUS_IPS" ]; then
    echo "[+] No remote external IPs found to investigate."
    exit 0
fi

echo "============================================================"
echo "[*] THREAT INTEL CTI ENRICHMENT"
echo "============================================================"
echo "Report will be saved to: $REPORT_OUT"
echo "Starting analysis at $(date)" > "$REPORT_OUT"
echo "" >> "$REPORT_OUT"

for IP in $SUSPICIOUS_IPS; do
    echo "------------------------------------------------------------" | tee -a "$REPORT_OUT"
    echo "TARGET IP: $IP" | tee -a "$REPORT_OUT"
    echo "------------------------------------------------------------" | tee -a "$REPORT_OUT"

    # 1. VirusTotal
    if [ -n "$VT_API_KEY" ]; then
        echo "    -> Querying VirusTotal..."
        VT_RESULT=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/ip_addresses/$IP" --header "x-apikey: $VT_API_KEY")
        VT_MALICIOUS=$(echo "$VT_RESULT" | jq -r '.data.attributes.last_analysis_stats.malicious // "0"')
        VT_OWNER=$(echo "$VT_RESULT" | jq -r '.data.attributes.as_owner // "Unknown"')
        echo "       - VT Malicious Hits: $VT_MALICIOUS" | tee -a "$REPORT_OUT"
        echo "       - ASN Owner: $VT_OWNER" | tee -a "$REPORT_OUT"
    fi

    # 2. AlienVault OTX
    if [ -n "$OTX_API_KEY" ]; then
        echo "    -> Querying AlienVault OTX..."
        OTX_RESULT=$(curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general" -H "X-OTX-API-KEY: $OTX_API_KEY")
        OTX_PULSES=$(echo "$OTX_RESULT" | jq -r '.pulse_info.count // "0"')
        echo "       - OTX Associated Campaigns (Pulses): $OTX_PULSES" | tee -a "$REPORT_OUT"
    fi

    # 3. GreyNoise
    if [ -n "$GN_API_KEY" ]; then
        echo "    -> Querying GreyNoise..."
        GN_RESULT=$(curl -s "https://api.greynoise.io/v3/community/$IP" -H "key: $GN_API_KEY")
        GN_CLASS=$(echo "$GN_RESULT" | jq -r '.classification // "Unknown"')
        GN_NAME=$(echo "$GN_RESULT" | jq -r '.name // "Unknown"')
        echo "       - GreyNoise Classification: $GN_CLASS" | tee -a "$REPORT_OUT"
        echo "       - GreyNoise Actor Name: $GN_NAME" | tee -a "$REPORT_OUT"
    fi

    # 4. AbuseIPDB
    if [ -n "$ABUSEIPDB_KEY" ]; then
        echo "    -> Querying AbuseIPDB..."
        ABIP_RESULT=$(curl -s -G https://api.abuseipdb.com/api/v2/check \
          --data-urlencode "ipAddress=$IP" \
          -d maxAgeInDays=90 \
          -H "Key: $ABUSEIPDB_KEY" \
          -H "Accept: application/json")
        ABIP_SCORE=$(echo "$ABIP_RESULT" | jq -r '.data.abuseConfidenceScore // "0"')
        ABIP_DOMAIN=$(echo "$ABIP_RESULT" | jq -r '.data.domain // "Unknown"')
        echo "       - AbuseIPDB Confidence Score: $ABIP_SCORE%" | tee -a "$REPORT_OUT"
        echo "       - Associated Domain: $ABIP_DOMAIN" | tee -a "$REPORT_OUT"
    fi

    # 5. Shodan
    if [ -n "$SHODAN_KEY" ]; then
        echo "    -> Querying Shodan..."
        SHODAN_RESULT=$(curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY")
        SHODAN_PORTS=$(echo "$SHODAN_RESULT" | jq -r '.ports | join(", ") // "None"')
        SHODAN_OS=$(echo "$SHODAN_RESULT" | jq -r '.os // "Unknown"')
        echo "       - Shodan Open Ports: $SHODAN_PORTS" | tee -a "$REPORT_OUT"
        echo "       - Shodan Fingerprinted OS: $SHODAN_OS" | tee -a "$REPORT_OUT"
    fi

    echo "" | tee -a "$REPORT_OUT"
    sleep 2 # Prevent rate-limiting on free API tiers
done

echo "============================================================"
echo "[*] CTI Enrichment Complete. See $REPORT_OUT"
echo "============================================================"