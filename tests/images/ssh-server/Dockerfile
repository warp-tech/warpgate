FROM alpine:3.14
RUN apk add openssh
RUN passwd -u root
ENTRYPOINT ["/usr/sbin/sshd", "-De"]
