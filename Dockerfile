# Reproducible build: pinned toolchain image, locked dependencies, no network
# needed after `cargo fetch`. verify.sh builds with this and compares hashes.
FROM rust:1.99.1-slim-bookworm@sha256:REPLACE_WITH_DIGEST_AT_RELEASE AS build
WORKDIR /src
COPY . .
ENV SOURCE_DATE_EPOCH=0 CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/usr/local/cargo=cargo"
RUN cargo build --locked --release -p unlinkable-inference-cli -p unlinkable-inference-reference-server \
 && mkdir /out && cp target/release/unlinkable-inference target/release/unlinkable-inference-reference-server /out/ \
 && cd /out && sha256sum * > SHA256SUMS

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
