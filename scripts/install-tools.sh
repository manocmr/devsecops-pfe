#!/usr/bin/env bash
set -euo pipefail

echo "[+] Installing prerequisites"

if ! command -v docker >/dev/null 2>&1; then
  echo "[-] Docker is required"
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x kubectl
  sudo mv kubectl /usr/local/bin/
fi

if ! command -v kind >/dev/null 2>&1; then
  curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
fi

echo "[+] Tools installed"
kubectl version --client
kind version
docker --version