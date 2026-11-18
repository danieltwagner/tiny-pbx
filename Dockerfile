# Static musl binary in an otherwise empty image (~1 MB).
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/tiny-pbx /tiny-pbx
# config + persisted registrations live in /data (must be writable by this user)
ENV PBX_CONFIG=/data/tiny-pbx.conf
USER 1000:1000
ENTRYPOINT ["/tiny-pbx"]
