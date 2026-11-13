#!/usr/bin/env bash
# Real-internet demo: resolver from the real roots with the example policy.
# 127.0.0.1 is a "default" subscriber (URLhaus only); 127.0.0.2 is "strict"
# (URLhaus + HaGeZi TIF).
set -u
cd "$(dirname "$0")/.."
./nanodns serve -policy feeds/policy.example.json -metrics 127.0.0.1:9155 >/tmp/nanodns-demo.log 2>&1 & S=$!
sleep 4
bad=$(grep -m1 -E '^[a-z0-9-]+\.[a-z]+ CNAME \.$' feeds/urlhaus-filter.rpz | awk '{print $1}')
for args in "example.com" "$bad" "-source 127.0.0.1 clickadu.net" "-source 127.0.0.2 clickadu.net"; do
  echo "== query $args"; ./nanodns query $args | head -3
done
curl -s 127.0.0.1:9155/metrics | grep -E '^nanodns_(blocked|queries)_total' | grep -v ' 0$'
kill $S; grep 'policy' /tmp/nanodns-demo.log
