#!/usr/bin/env bash
# Usage: ./nmap_runner.sh 172.17.0.2 data/raw/masscan_172.17.0.2.json
TARGET=$1
MASSCAN_JSON=$2
OUTDIR="../data/nmap"
mkdir -p $OUTDIR
if [ -z "$TARGET" ] || [ -z "$MASSCAN_JSON" ]; then
  echo "Usage: $0 <target> <masscan_json>"
  exit 1
fi
# extract ports (simple jq recommended)
PORTS=$(jq -r '.[] | select(.ip) | .ports[]?.port' $MASSCAN_JSON | sort -n | uniq | paste -sd, -)
if [ -z "$PORTS" ]; then
  echo "No ports found in $MASSCAN_JSON — default to 80,443,22"
  PORTS="22,80,443"
fi
nmap -sV -p $PORTS -oX $OUTDIR/nmap_${TARGET}.xml $TARGET
echo "nmap xml: $OUTDIR/nmap_${TARGET}.xml"
