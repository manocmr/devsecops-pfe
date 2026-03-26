#!/usr/bin/env bash
set -euo pipefail

echo "[+] Deploying manifests"
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

echo "[+] Waiting for deployment"
kubectl -n security-test rollout status deployment/vulnerable-app --timeout=120s

echo "[+] Current resources"
kubectl -n security-test get all