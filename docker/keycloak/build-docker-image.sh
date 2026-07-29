#!/bin/bash
set -euo pipefail

# Get absolute path to the directory where the script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Assume Dockerfile is in the same dir as the script
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

docker build --no-cache -f $DOCKERFILE -t keycloak-api $SCRIPT_DIR

