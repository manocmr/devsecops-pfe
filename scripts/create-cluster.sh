#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="security-lab"

if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
  echo "[+] Cluster ${CLUSTER_NAME} already exists"
else
  echo "[+] Creating Kind cluster"
  kind create cluster --config kind/kind-config.yaml
fi

echo "[+] Waiting for cluster nodes"
kubectl cluster-info
kubectl get nodes -o wide