#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "Installation of Software Components"
echo "------------------------------------"

python3 ./internal/install.py

exit 0