FROM rust:1.99-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p oauth-proxy \
 && cp target/release/oauth-proxy /oauth-proxy

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin oauth-proxy
COPY --from=build /oauth-proxy /usr/local/bin/oauth-proxy
USER oauth-proxy
EXPOSE 5200
ENTRYPOINT ["/usr/local/bin/oauth-proxy"]
