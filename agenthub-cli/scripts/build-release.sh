#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install -q build
python -m build
python -c "import hashlib,pathlib; p=pathlib.Path('dist');
print('\n'.join(f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}' for f in sorted(p.iterdir()) if f.is_file()))" > dist/SHA256SUMS
cat dist/SHA256SUMS
