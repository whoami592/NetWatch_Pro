#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
g++ -std=c++11 -O2 -Wall -Wextra -Wpedantic -pthread main.cpp -o NetWatchPro
printf 'Built NetWatchPro. Run ./NetWatchPro\n'
