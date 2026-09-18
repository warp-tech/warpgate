# syntax=docker/dockerfile:1.3-labs
# hadolint global ignore=DL3008
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates-java nodejs default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install --locked just@1.4.0

COPY . /opt/warpgate

# Needed to correctly embed the version number and the dirty state flag
COPY .git/ /opt/warpgate/.git/

# for rust-embed determinism
ENV SOURCE_DATE_EPOCH=0

WORKDIR /opt/warpgate

# Which frontend to build.
#
# The app tests `import.meta.env.VITE_NEW_UI === 'true'` in admin/index.ts and
# gateway/index.ts, so ONLY the exact string "true" selects the redesigned UI.
# A value of `1` would silently build the old one, which is a bad way to lose
# twenty minutes, so the common truthy spellings are normalised here and the
# resolved value is echoed into the build log.
#
# Vite substitutes this at build time and Rollup drops the unused shell, so the
# image contains one UI, not both.
ARG VITE_NEW_UI=false

RUN case "${VITE_NEW_UI,,}" in \
      1|true|yes|on)  VITE_NEW_UI=true ;; \
      0|false|no|off|"") VITE_NEW_UI=false ;; \
      *) echo "VITE_NEW_UI: unrecognised value '${VITE_NEW_UI}'" >&2; exit 1 ;; \
    esac \
    && export VITE_NEW_UI \
    && echo "=== building frontend with VITE_NEW_UI=${VITE_NEW_UI} ===" \
    && just npm ci \
    && just openapi \
    && just npm run build \
    && cargo build --features mysql,postgres,rdp-openssl-tls --release

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
LABEL maintainer=heywoodlh
ARG USER_ID=1000

# Re-declared: an ARG from an earlier stage is not in scope here. Recorded as a
# label so `docker inspect` answers "which UI is in this image?" — the two
# images are otherwise indistinguishable from the outside.
ARG VITE_NEW_UI=false
LABEL org.warpgate.new-ui="${VITE_NEW_UI}"

ENV DEBIAN_FRONTEND=noninteractive
RUN <<EOF
  set -xe
  apt-get -y update -qq
  apt-get install --no-install-recommends --no-install-suggests -y \
    ca-certificates wget sqlite3
  apt-get clean
  rm -rf /var/lib/apt/lists/*
EOF

# RUN adduser warpgate --system --home /data
RUN adduser warpgate --disabled-password --gecos "" --uid ${USER_ID} --home /data --shell /usr/sbin/nologin

COPY --from=build /opt/warpgate/target/release/warpgate /usr/local/bin/warpgate

VOLUME /data

ENV WARPGATE_CONFIG=/data/warpgate.yaml

HEALTHCHECK CMD warpgate healthcheck

ENV DOCKER=1
USER warpgate
ENTRYPOINT ["warpgate"]
CMD ["run"]
