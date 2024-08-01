#!/usr/bin/env sh
john --wordlist=wordlist.txt "$@"
echo ""
echo "=== Results: ==="
john --show "$@"
