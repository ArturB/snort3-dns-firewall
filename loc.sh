#!/bin/bash

SRC_DIR="src"
FILE_EXTS=".h .hpp .cc .cpp CMakeLists.txt"
SRC_FILES="CMakeLists.txt"

for i in $FILE_EXTS
do
    SRC_FILES="$SRC_FILES $( find $SRC_DIR -type f -name *$i )"
done

cat $SRC_FILES | wc -l
