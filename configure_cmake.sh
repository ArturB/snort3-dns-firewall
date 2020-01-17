#!/bin/sh

set -e

# check for `cmake` command
type cmake > /dev/null 2>&1 || {
    echo "\
This package requires CMake, please install it first, then you may
use this configure script to access CMake equivalent functionality.\
" >&2;
    exit 1;
}

# set defaults
sourcedir="$( cd "$( dirname "$0" )" && pwd )"
builddir=build
prefix=/usr/local/snort

if [ -d $builddir ]; then
    # If build directory exists, clear its content
    if [ -f $builddir/CMakeCache.txt ]; then
        # If the CMake cache exists, delete it so that this configuration
        # is not tainted by a previous one
        rm -f $builddir/CMakeCache.txt
    fi
else
    # Create build directory
    mkdir -p $builddir
fi

echo "Build Directory : $(pwd)/$builddir"
echo "Source Directory: $sourcedir"
cd $builddir

cmake \
    -DCMAKE_CXX_FLAGS:STRING="$CXXFLAGS $CPPFLAGS" \
    -DCMAKE_C_FLAGS:STRING="$CFLAGS $CPPFLAGS" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    $sourcedir
