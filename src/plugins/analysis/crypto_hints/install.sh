#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "        Install Crypto Hints        "
echo "------------------------------------"

rm -rf signatures
(mkdir signatures && cd signatures || exit && wget https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar)
	
exit 0
