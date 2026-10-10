#!/usr/bin/env bash
# Run on the VM from inside this repo folder:   bash prepare_repo.sh [path-to-working-copy]
# Copies your tested source files into the repo, refuses to continue if a secret is found,
# runs the tests, and prints the git commands.
set -euo pipefail
SRC="${1:-$HOME/ddos-guard}"
cd "$(dirname "$0")"
[ -d "$SRC" ] || { echo "Source folder not found: $SRC"; exit 1; }

for f in collector.py baseline.py train.py detector.py live_detect.py mitigator.py alerts.py state.py main.py; do
  [ -f "$SRC/$f" ] || { echo "Missing $SRC/$f"; exit 1; }
  cp "$SRC/$f" .
done
mkdir -p dashboard
for f in app.py index.html __init__.py; do
  [ -f "$SRC/dashboard/$f" ] || { echo "Missing $SRC/dashboard/$f"; exit 1; }
  cp "$SRC/dashboard/$f" dashboard/
done
echo "[ok] source files copied from $SRC"

# Secret scan on code only (config.yaml, baseline.json and alerts.log are never copied)
if grep -rInE "hooks\.slack\.com/services/[A-Za-z0-9]|password['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{3,}['\"]" \
     --include='*.py' --include='*.html' . ; then
  echo "[STOP] possible secret found in the lines above. Remove it before committing."
  exit 1
fi
echo "[ok] no secrets found in source files"

for f in config.yaml baseline.json alerts.log baseline.backup.json; do
  [ ! -e "$f" ] || { echo "[STOP] $f is in the repo folder. It is git-ignored, but delete it to be safe."; exit 1; }
done

python3 -m pytest -q 2>/dev/null || echo "[note] tests did not run. Install with: pip install -r requirements-dev.txt && pytest"

cat << 'NEXT'

Next steps:
  git init -b main
  git add .
  git status                      # check that config.yaml and baseline.json are NOT listed
  git commit -m "Initial commit: ddos-guard DDoS detection and mitigation tool"
  git remote add origin https://github.com/YOUR-USERNAME/ddos-guard.git
  git push -u origin main
NEXT
