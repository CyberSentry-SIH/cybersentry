#!/usr/bin/env bash
set -e

echo "=== Running CyberSentry Backend Quality Checks ==="
export PYTHONPATH=.
python3 -m pytest backend/tests

if command -v ruff &> /dev/null; then
    echo "=== Running Ruff linter ==="
    ruff check backend/
else
    echo "Ruff not found in environment, skipping python linting."
fi

echo "=== Running Frontend Checks ==="
cd frontend
if [ -d "node_modules" ]; then
    npm run lint
else
    echo "node_modules not found, skipping frontend lint."
fi
cd ..

echo "=== All checks completed successfully! ==="
