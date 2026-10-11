FROM rust:1.99-trixie AS build
WORKDIR /src
# Cargo features of the image; e.g. --build-arg FEATURES= for a build without the rate limit.
ARG FEATURES=rate-limit
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p bff --no-default-features --features "$FEATURES" \
 && cp target/release/bff /bff

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin bff
COPY --from=build /bff /usr/local/bin/bff
USER bff
EXPOSE 5100
ENTRYPOINT ["/usr/local/bin/bff"]
