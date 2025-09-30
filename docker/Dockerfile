# syntax=docker/dockerfile:1.3-labs
# hadolint global ignore=DL3008
FROM rust:1.85.0-bullseye@sha256:0fdb1727a6c81e0811df9d67bd6defa9a4a07d2a44373ab0a017aedad9fcba3f AS build

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates-java nodejs openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install just

COPY . /opt/warpgate

# Needed to correctly embed the version number and the dirty state flag
COPY .git/ /opt/warpgate/.git/

# for rust-embed determinism
ENV SOURCE_DATE_EPOCH=0

WORKDIR /opt/warpgate

RUN just npm ci \
    && just openapi \
    && just npm run build \
    && cargo build --features mysql,postgres --release

FROM debian:bullseye-20250520@sha256:cf48c31af360e1c0a0aedd33aae4d928b68c2cdf093f1612650eb1ff434d1c34
LABEL maintainer=heywoodlh
ARG USER_ID=1000

ENV DEBIAN_FRONTEND=noninteractive
RUN <<EOF
  set -xe
  apt-get -y update -qq
  apt-get install --no-install-recommends --no-install-suggests -y \
    ca-certificates wget
  apt-get clean
  rm -rf /var/lib/apt/lists/*
EOF

# RUN adduser warpgate --system --home /data
RUN adduser warpgate --disabled-password --gecos "" --uid ${USER_ID} --home /data --shell /usr/sbin/nologin

COPY --from=build /opt/warpgate/target/release/warpgate /usr/local/bin/warpgate

VOLUME /data

HEALTHCHECK CMD warpgate healthcheck

ENV DOCKER=1

USER warpgate
ENTRYPOINT ["warpgate", "--config", "/data/warpgate.yaml"]
CMD ["run"]
