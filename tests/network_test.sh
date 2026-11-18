#!/bin/sh
# Network test (Part 3). Starts the server, then runs two clients at the same time.
# Lines are sent slowly, like a person typing, so the flood rule (15 requests in 5 seconds from one IP) is not triggered.
# Usage: sh tests/network_test.sh [port]
PORT=${1:-6100}
DATA=$(mktemp -d)

slow() { while IFS= read -r line; do echo "$line"; sleep 1; done; }

SENTINEL_DIR="$DATA" ./sentinel-server "$PORT" > "$DATA/server.out" 2>&1 &
SERVER=$!
sleep 1

printf 'REGISTER khaled secret123\nLOGIN khaled secret123\nWHOAMI\nREQUEST 6\nSEARCH hello world\nQUIT\n' \
    | slow | ./sentinel-client 127.0.0.1 "$PORT" > "$DATA/client1.out" &
C1=$!
printf 'REGISTER rawad rawad2026\nLOGIN rawad rawad2026\nREQUEST 5\nREQUEST 6\nWHOAMI\nQUIT\n' \
    | slow | ./sentinel-client 127.0.0.1 "$PORT" > "$DATA/client2.out" &
C2=$!
wait $C1 $C2

echo "--- client 1"; cat "$DATA/client1.out"
echo "--- client 2"; cat "$DATA/client2.out"

echo "--- attacker (injection, gets blocked)"
printf 'SEARCH q=1 UNION SELECT password FROM users\nWHOAMI\n' | slow | ./sentinel-client 127.0.0.1 "$PORT"

kill -INT $SERVER
wait $SERVER
echo "--- server log"; cat "$DATA/sentinel.log"
rm -rf "$DATA"
