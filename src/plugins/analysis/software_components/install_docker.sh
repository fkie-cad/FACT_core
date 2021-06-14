#!/usr/bin/env bash

# change cwd to this file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

# build docker container
docker build -t fact/format_string_resolver docker || exit 1
