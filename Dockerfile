FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev ca-certificates

WORKDIR /usr/src/trojan-rust

COPY Cargo.toml Cargo.lock ./
COPY benches ./benches

RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY src ./src

RUN cargo build --release --locked

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch

LABEL org.opencontainers.image.title="trojan-rust"
LABEL org.opencontainers.image.description="Lightweight, high-performance Trojan proxy server"
LABEL org.opencontainers.image.source="https://github.com/yourusername/trojan-rust"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=builder /usr/src/trojan-rust/target/release/trojan-rust /trojan-rust
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 443/tcp
EXPOSE 443/udp

ENTRYPOINT ["/trojan-rust"]
CMD ["-c", "/etc/trojan-rust/config.toml"]
