#!/bin/bash
set -e
# Check Keycloak health endpoint on management port
exec 3<>/dev/tcp/localhost/9000
echo -e "GET /health HTTP/1.1\r\nHost: localhost:9000\r\nConnection: close\r\n\r\n" >&3
response=$(head -n1 <&3)
exec 3<&-
exec 3>&-

# Check if we got a 200 OK response
echo "$response" | grep "200 OK" >/dev/null
ERROR=$?
exit $ERROR
