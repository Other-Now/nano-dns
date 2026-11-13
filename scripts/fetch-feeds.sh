#!/usr/bin/env bash
# Download the real data the experiments use into feeds/ (gitignored).
#   - HaGeZi Threat Intelligence Feeds, medium (RPZ, ~730k rules; GPL-3.0)
#   - malware-filter's URLhaus-derived RPZ (~2k rules; data from abuse.ch URLhaus, CC0)
#   - Tranco top-1M list (for the difftest and the false-positive check)
# abuse.ch retired its own free RPZ/hostfile downloads (HTTP 410), hence the mirrors.
set -euo pipefail
cd "$(dirname "$0")/../feeds"
curl -fsSL -o hagezi-tif-medium.rpz https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif.medium.txt
curl -fsSL -o urlhaus-filter.rpz    https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-rpz.conf
curl -fsSL -o tranco.zip            https://tranco-list.eu/top-1m.csv.zip
unzip -o -q tranco.zip && rm tranco.zip
wc -l *.rpz top-1m.csv
