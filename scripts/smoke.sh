#!/usr/bin/env bash
# Start the simulator and the resolver, run a few queries, stop both.
set -u
cd "$(dirname "$0")/.."
./nanodns authsim -port 5300 >/tmp/nanodns-authsim.log 2>&1 & A=$!
./nanodns serve -sim-port 5300 "$@" >/tmp/nanodns-serve.log 2>&1 & S=$!
sleep 1
for q in www.victim.com api.victim.com host5.popular.com www.shop.com www.shop.com; do
  ./nanodns query $q | head -1 | sed "s/^/$q  /"
done
kill $A $S; wait 2>/dev/null
