FROM alpine:3.14
RUN apk add openssh curl
RUN passwd -u root
ENTRYPOINT ["/usr/sbin/sshd", "-De"]
