#!/bin/bash

echo "[1] Running io tests..."

echo "Running server..."
./out/test_io_server &

echo "Running proxy..."
./out/test_io_proxy &

echo "Running client..."
./out/test_io_client &

echo "Done."