# syntax=docker/dockerfile:1.3-labs
FROM rust:1.79.0-bullseye AS build

ENV DEBIAN_FRONTEND noninteractive

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get update \
    && apt-get install -y ca-certificates-java nodejs openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install just

COPY . /opt/warpgate

ENV SOURCE_DATE_EPOCH=0 # for rust-embed determinism
RUN cd /opt/warpgate \
    && just npm ci \
    && just openapi \
    && just npm run build \
    && cargo build --features mysql,postgres --release

FROM debian:bullseye-20221024
LABEL maintainer=heywoodlh

ENV DEBIAN_FRONTEND noninteractive
RUN <<EOF
  set -xe
  apt-get -y update -qq
  apt-get install --no-install-recommends -y \
    ca-certificates
  apt clean
EOF

COPY --from=build /opt/warpgate/target/release/warpgate /usr/local/bin/warpgate

VOLUME /data

ENV DOCKER 1

ENTRYPOINT ["warpgate", "--config", "/data/warpgate.yaml"]
CMD ["run"]
