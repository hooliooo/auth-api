FROM quay.io/keycloak/keycloak:26.7.0 AS builder

ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=false
ENV KC_TRACING_ENABLED=false
ENV KC_TRACING_SERVICE_NAME=keycloak-api
ENV KC_DB=postgres

# Build the optimized image
RUN /opt/keycloak/bin/kc.sh build
RUN /opt/keycloak/bin/kc.sh show-config

## Runtime env
FROM quay.io/keycloak/keycloak:26.7.0
# Copy optimzed image data and custom artifacts
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Also set same default features in runtime env
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=false
ENV KC_TRACING_ENABLED=false
ENV KC_TRACING_SERVICE_NAME=keycloak-api
ENV KC_DB=postgres

COPY --chown=1000:0 --chmod=755 healthcheck.sh /opt/keycloak/bin/healthcheck.sh
HEALTHCHECK --start-period=180s CMD /opt/keycloak/bin/healthcheck.sh

# Specific UserID is not important, and can be set externally. To avoid potential conflicts with host UserID it should be >= 10000
USER 13280

# Set entrypoint to kc command script
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
