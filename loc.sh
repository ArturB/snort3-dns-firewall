#!/bin/bash

NO_COMMENTS=""
if [[ $1 == "nocom" ]] ; then
    NO_COMMENTS="true"
else
    NO_COMMENTS="false"
fi

SRC_DIR="src"
FILE_EXTS=".h .hpp .cc .cpp CMakeLists.txt"
SRC_FILES="CMakeLists.txt"

for i in $FILE_EXTS
do
    SRC_FILES="$SRC_FILES $( find $SRC_DIR -type f -name *$i )"
done

if [[ NO_COMMENTS == "true" ]] ; then
    cat $SRC_FILES | grep -v '//' | grep -v '#' | wc -l
else
    cat $SRC_FILES | wc -l
fi
