#!/bin/bash

docker build -t ev-rockylinux9-build -f docker/Dockerfile.rocky9 .
# docker build -t ev-rockylinux8-build -f docker/Dockerfile.rocky8 .

