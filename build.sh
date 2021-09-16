#!/bin/bash

clear
/usr/bin/cmake -DCMAKE_BUILD_TYPE:STRING=Debug -H./ -B./Build -G "Unix Makefiles" || exit 1
make -C Build/ all
