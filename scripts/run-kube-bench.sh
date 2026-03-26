#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports

echo "[+] Running kube-bench"
echo "[!] Note: on Kind/Docker, kube-bench results are limited and not equal to a real node CIS audit"

docker run --rm \
  --pid=host \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  -v /usr/bin:/usr/local/mount-from-host/bin:ro \
  -v /lib/systemd:/lib/systemd:ro \
  -v /srv/kubernetes:/srv/kubernetes:ro \
  aquasec/kube-bench:latest \
  --json \
  > reports/kube-bench-report.json || true

echo "[+] kube-bench report saved to reports/kube-bench-report.json"