#!/bin/sh

BUILD_DIR="build"

if [ "$1" = "clean" ]; then
  rm -rf $BUILD_DIR
fi

if [ ! -d $BUILD_DIR ]; then
  mkdir $BUILD_DIR || exit 1
fi

cd build
cmake ../ #-DMTM_EMULATOR=ON 
make
cd ..

exit 0

