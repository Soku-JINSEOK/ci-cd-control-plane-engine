#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

python3 scripts/publication_worktree_check.py
python3 scripts/resolve-registry.py --repository ExampleOrg/sample-widget >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/public_contract_evidence.py \
  --source-sha "${SOURCE_SHA:-$(git rev-parse HEAD)}" \
  --output "${EVIDENCE_OUTPUT:-public-contract-evidence.json}"
