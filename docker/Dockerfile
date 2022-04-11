FROM rust:bullseye AS build

ENV DEBIAN_FRONTEND noninteractive

RUN curl -fsSL https://deb.nodesource.com/setup_17.x | bash - \
    && apt-get update \
    && apt-get install -y nodejs openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g yarn \
    && cargo install just

RUN git clone https://github.com/Eugeny/warpgate /opt/warpgate \
    && cd /opt/warpgate \
    && just yarn \
    && just yarn build \
    && cargo build

FROM debian:bullseye
LABEL maintainer=heywoodlh

COPY --from=build /opt/warpgate/target/debug/warpgate /usr/local/bin/warpgate
COPY run.sh /run.sh
COPY expect.sh /expect.sh

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get install -y expect openssl \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 2222
EXPOSE 8888

VOLUME /data

ENTRYPOINT ["/run.sh"]
