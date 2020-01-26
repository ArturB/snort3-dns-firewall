#!/bin/bash

cd build
make -j $(nproc) $@
cd ..
