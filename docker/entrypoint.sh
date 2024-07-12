#!/bin/bash

ls -la
if [ -d uring_build ]; then
    cd uring_build && ctest --output-on-failure
    cd ..
fi

cd epoll_build && ctest --output-on-failure

