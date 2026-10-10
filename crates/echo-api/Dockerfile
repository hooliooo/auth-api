FROM rust:1.98-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p echo-api \
 && cp target/release/echo-api /echo-api

FROM debian:trixie-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin echo
COPY --from=build /echo-api /usr/local/bin/echo-api
USER echo
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/echo-api"]
