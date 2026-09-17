#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
for tool in go vault; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
# HTTP runner only. PostgreSQL lifecycle tests run separately and remain required.
go test ./internal/brokercore/... ./internal/mitm/... ./internal/hashicorp/... ./internal/requestlog/... ./internal/workloadidentity/... -count=1
go test -tags realvault ./internal/mitm -run '^TestRealVault_HTTPAuthorization$' -count=1 -timeout 90s
# Required request-time resolution: rotation and deletion must apply without synchronization.
go test -tags realvault,credentialproxyacceptance ./internal/mitm -run '^TestRealVault_RequestTimeResolution$|^TestRealVault_StrictHTTPProfile$' -count=1 -v -timeout 90s
