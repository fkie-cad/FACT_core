#!/usr/bin/env bash

echo "------------------------------------"
echo "    building the documentation      "
echo "------------------------------------"

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

make clean html || exit 1

echo "moving html to ../docs"
cp -a _build/html/. ../docs/ || exit 1
