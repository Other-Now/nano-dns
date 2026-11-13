#!/usr/bin/env bash
# Shows that single-socket timeouts at high concurrency are kernel UDP receive-buffer drops.
cd "$(dirname "$0")/.."
rb() { awk '/^Udp:/{n++; if(n==1){for(i=1;i<=NF;i++)h[i]=$i} else {for(i=1;i<=NF;i++) if(h[i]=="RcvbufErrors") print $i}}' /proc/net/snmp; }
./nanodns authsim -port 5300 -popular 1000 >/dev/null 2>&1 & A=$!
for sk in 1 4; do
  ./nanodns serve -sim-port 5300 -sockets $sk -metrics "" >/dev/null 2>&1 & S=$!
  sleep 1; ./nanodns bench -c 32 -d 2s >/dev/null
  r0=$(rb); out=$(./nanodns bench -c 256 -d 8s); r1=$(rb)
  echo "sockets=$sk UDP RcvbufErrors +$((r1-r0)) | $out"
  kill $S; wait $S 2>/dev/null
done
kill $A
echo "net.core.rmem_default=$(cat /proc/sys/net/core/rmem_default)"
