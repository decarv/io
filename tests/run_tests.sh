#!/bin/bash

echo "[1] Running io tests..."

echo "Running server..."
./out/test_io_server &
SERVER_PID=$!

echo "Running proxy..."
./out/test_io_proxy &
PROXY_PID=$!

echo "Running client..."
./out/test_io_client &
CLIENT_PID=$!

# Wait for the client process to complete
wait $CLIENT_PID

# Once the client is done, terminate the server and proxy
echo "Terminating server and proxy..."
kill $SERVER_PID $PROXY_PID

echo "Done."
