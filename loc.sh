#!/bin/bash

SRC_DIR="cmake src"
FILE_EXTS=".cmake .h .hpp .cc .cpp .txt"
SRC_FILES="CMakeLists.txt"

for i in $FILE_EXTS
do
    SRC_FILES="$SRC_FILES $( find $SRC_DIR -type f -name *$i )"
done

echo -n "With comments included: "
cat $SRC_FILES | wc -l
echo -n "Without comments:       "
cat $SRC_FILES | grep -v '//' | grep -v '#' | wc -l
