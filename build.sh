#!/bin/bash
ROOT=$(pwd)
rm -rf $ROOT/build/*
cd $ROOT/build
cmake .. -DCMAKE_BUILD_TYPE="Debug"
make
