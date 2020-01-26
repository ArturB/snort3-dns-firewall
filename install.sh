#!/bin/bash

cd build
sudo make install -j $(nproc) $@
cd ..
