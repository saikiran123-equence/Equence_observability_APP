#!/bin/bash
echo ""
echo "========================================"
echo "   Equence Infra Monitor"
echo "========================================"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
  echo "ERROR: Node.js is not installed."
  echo "Download it from https://nodejs.org (LTS version)"
  exit 1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
  echo "Installing dependencies..."
  npm install
  echo ""
fi

# Run setup if .env missing
if [ ! -f ".env" ]; then
  echo "First-time setup:"
  node setup.js
  echo ""
fi

echo "Starting server..."
node backend/src/server.js
