FROM quay.io/keycloak/keycloak:26.8.0 AS builder

# Build options, fixed into the optimized build
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_TRACING_ENABLED=true
ENV KC_FEATURES=user-event-metrics
ENV KC_EVENT_METRICS_USER_ENABLED=true
ENV KC_DB=postgres

RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/

COPY --chown=1000:0 --chmod=755 healthcheck.sh /opt/keycloak/bin/healthcheck.sh
HEALTHCHECK --interval=5s --start-period=180s --start-interval=2s CMD /opt/keycloak/bin/healthcheck.sh

# Specific UserID is not important, and can be set externally. To avoid potential conflicts with host UserID it should be >= 10000
USER 13280

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
