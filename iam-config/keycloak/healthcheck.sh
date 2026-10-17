#!/bin/bash
set -e
# Check Keycloak readiness endpoint on management port
exec 3<>/dev/tcp/localhost/9000
echo -e "GET /health/ready HTTP/1.1\r\nHost: localhost:9000\r\nConnection: close\r\n\r\n" >&3
head -n1 <&3 | grep -q "200 OK"
