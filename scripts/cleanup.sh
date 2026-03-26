#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="security-lab"

echo "[+] Deleting Kind cluster"
kind delete cluster --name "${CLUSTER_NAME}" || true