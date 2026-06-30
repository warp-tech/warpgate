FROM debian:bookworm-slim
# tigervnc-standalone-server provides Xtigervnc; tigervnc-tools provides the
# password utility (tigervncpasswd) used for the VncAuth target-auth test.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tigervnc-standalone-server tigervnc-tools \
    && rm -rf /var/lib/apt/lists/* \
    && (command -v tigervncpasswd || command -v vncpasswd)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 5900
ENTRYPOINT ["/entrypoint.sh"]
