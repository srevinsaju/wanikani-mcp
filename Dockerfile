FROM rust:1.92-alpine AS builder
WORKDIR /build
RUN apk add --no-cache musl-dev pkgconf openssl-dev openssl-libs-static
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/wanikani-mcp /wanikani-mcp
EXPOSE 3000
ENV BIND_ADDRESS=0.0.0.0:3000
ENV PUBLIC_ADDRESS=http://localhost:3000
ENTRYPOINT ["/wanikani-mcp"]
