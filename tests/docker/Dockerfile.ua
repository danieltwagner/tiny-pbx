# Non-pjsip SIP user agents for the interop tests (see tests/README.md):
# baresip 1.0 and linphonec 5.1 from Debian bookworm.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        baresip-core linphone-cli procps iproute2 \
    && rm -rf /var/lib/apt/lists/*
