# syntax=docker/dockerfile:1.3-labs
# hadolint global ignore=DL3008
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build

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

RUN just npm ci \
    && just openapi \
    && just npm run build \
    && cargo build --features mysql,postgres,rdp-openssl-tls --release

ARG USER_ID=1000
RUN adduser warpgate --disabled-password --gecos "" --uid ${USER_ID} --home /data --shell /usr/sbin/nologin \
    && mkdir -p /data \
    && chown -R ${USER_ID}:${USER_ID} /data

FROM gcr.io/distroless/cc-debian13
LABEL maintainer=heywoodlh

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build --chown=warpgate:warpgate /data /data
COPY --from=build /opt/warpgate/target/release/warpgate /usr/local/bin/warpgate

VOLUME /data

ENV WARPGATE_CONFIG=/data/warpgate.yaml

HEALTHCHECK CMD ["/usr/local/bin/warpgate", "healthcheck"]

ENV DOCKER=1
USER warpgate
ENTRYPOINT ["/usr/local/bin/warpgate"]
CMD ["run"]
