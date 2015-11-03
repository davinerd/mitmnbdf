#! /usr/bin/env bash
#
# This script will copy the bdf repository into python library path.
# It's a dirty but quick hack. Sorry.
#

PYLIBPATH=$(python -c "from distutils.sysconfig import *; print(get_python_lib())")
BDFPATH="${PWD}/bdf"

if [ ! -e $BDFPATH ]; then
    echo "Error: bdf not found in ${BDFPATH}"
    exit 1
fi

if [ ! "$PYLIBPATH" ]; then
    echo "Weird. python library path not found."
    exit 1
fi

if [ ! -w "$PYLIBPATH" ]; then
    echo "Error: $PYLIBPATH permission denied. Maybe root?"
    exit 1
fi

echo "Copying ${BDFPATH} to ${PYLIBPATH}..."
cp -r "${BDFPATH}" "$PYLIBPATH"
echo "DONE! Enjoy"