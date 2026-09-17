#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
for tool in go vault; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
go test ./internal/actionref/... ./internal/mitm/... ./internal/brokercore/... -count=1
go test -tags realvault ./internal/mitm -run '^TestRealVault_HTTPAuthorization$' -count=1 -v -timeout 90s
