#!/bin/bash

if ! $(command -v docker &> /dev/null );
then
    echo "Error: docker is not installed." >&2
    exit 1
fi

cd ..
docker build -t ev-rockylinux9-test-build -f docker/Dockerfile.rocky9 .
docker run --privileged -it ev-rockylinux9-test-build

docker build -t ev-rockylinux8-test-build -f docker/Dockerfile.rocky8 .
docker run --privileged -it ev-rockylinux8-test-build

