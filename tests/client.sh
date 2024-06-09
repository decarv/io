#!/bin/bash

num_clients=10 
num_messages=100



for client in $(seq 1 $num_clients); do
  for message in $(seq 1 $num_messages); do
     sleep $((RANDOM % 5))
     echo "Message $message from client $client" | nc -q 0 localhost 8800
  done
done

wait  # Wait for all background processes to complete

