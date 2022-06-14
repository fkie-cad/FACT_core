#!/usr/bin/env sh
john --wordlist=10k-most-common.txt "$@"
echo ""
echo "=== Results: ==="
john --show "$@"
