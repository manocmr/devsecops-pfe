#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports

echo "[+] Running kube-hunter"

docker run --rm --network host aquasec/kube-hunter:latest \
  --active \
  --report json \
  > reports/kube-hunter-report.json || true

echo "[+] kube-hunter report saved to reports/kube-hunter-report.json"