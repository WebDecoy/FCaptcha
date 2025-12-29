#!/bin/bash
# FCaptcha Test Runner
# Starts a server and runs the test suite

set -e

cd "$(dirname "$0")"

SERVER=${1:-node}  # Default to node, can pass 'go' or 'python'

echo "Starting $SERVER server..."

case $SERVER in
  node)
    cd server-node
    npm install --silent 2>/dev/null || npm install
    node server.js &
    ;;
  go)
    cd server-go
    go run . &
    ;;
  python)
    cd server-python
    pip install -r requirements.txt -q 2>/dev/null || pip install -r requirements.txt
    python server.py &
    ;;
  *)
    echo "Unknown server: $SERVER"
    echo "Usage: ./test.sh [node|go|python]"
    exit 1
    ;;
esac

SERVER_PID=$!
cd ..

# Wait for server to start
echo "Waiting for server to start..."
for i in {1..10}; do
  if curl -s http://localhost:3000/health > /dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

# Run tests
echo ""
node test/test-detection.js
TEST_EXIT=$?

# Cleanup
kill $SERVER_PID 2>/dev/null || true

exit $TEST_EXIT
