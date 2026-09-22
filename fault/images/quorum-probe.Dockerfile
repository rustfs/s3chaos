# Build with immutable, architecture-matched builder and RustFS references.
ARG BUILDER_IMAGE
ARG RUSTFS_IMAGE
FROM ${BUILDER_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin s3chaos-quorum-probe
FROM ${RUSTFS_IMAGE}
COPY --from=build /src/target/release/s3chaos-quorum-probe /usr/local/bin/s3chaos-quorum-probe
