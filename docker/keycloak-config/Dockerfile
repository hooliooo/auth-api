# keep version in sync with keycloak/Dockerfile
FROM quay.io/keycloak/keycloak:26.5.5 AS keycloak

FROM eclipse-temurin:21.0.10_7-jre-jammy
RUN apt update
RUN apt install -y curl jq bash

ENV kcadm=/opt/keycloak/bin/kcadm.sh
COPY --from=keycloak $kcadm $kcadm
COPY --from=keycloak /opt/keycloak/bin/client /opt/keycloak/bin/client
