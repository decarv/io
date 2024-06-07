#!/bin/bash

for i in $(seq 1 100); do
  sleep 1
  echo "This is message $i" | nc 'localhost' 8800
done

