#!/usr/bin/env bash
# Usage: ./masscan_runner.sh 172.17.0.2
TARGET=$1
OUTDIR="../data/raw"
mkdir -p $OUTDIR
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target>"
  exit 1
fi
# rate는 네트워크/환경에 맞게 조절하세요
masscan $TARGET -p1-65535 --rate=1000 -oJ $OUTDIR/masscan_${TARGET}.json
echo "masscan output: $OUTDIR/masscan_${TARGET}.json"
