# The ui:// views: single-file HTML that the server embeds at compile time.
# They import the sign-in pages' tokens.css from templates/.
FROM docker.io/oven/bun:1.4.2 AS views
WORKDIR /src/ui
COPY ui/package.json ui/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui ./
COPY templates /src/templates
RUN bun run build

FROM docker.io/library/rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY templates templates
COPY --from=views /src/ui/dist ui/dist
# Migrations (src/auth/migrations), askama templates and the views compile
# into the binary, so it is the only thing the runtime image needs.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/wanikani-mcp /wanikani-mcp \
    && mkdir /data

# glibc, libssl and a CA bundle (for HTTPS to WaniKani), and nothing else.
# The SQLite database (and its -wal/-shm files) in /data is the only thing
# the server writes, so the root filesystem can be read-only.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /wanikani-mcp /usr/local/bin/wanikani-mcp
# Owned by the server's uid, so a new Docker volume at /data is writable.
COPY --from=build --chown=10001:10001 /data /data
USER 10001:10001
ENV BIND_ADDRESS=0.0.0.0:8080 \
    DATABASE=sqlite:///data/wanikani-mcp.db \
    RUST_LOG=wanikani_mcp=info
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wanikani-mcp"]
