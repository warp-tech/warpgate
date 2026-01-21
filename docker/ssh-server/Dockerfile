# SSH server for testing file transfer permissions
FROM alpine:3.19

RUN apk add --no-cache openssh openssh-sftp-server

# Create test user with password 'test'
RUN adduser -D -s /bin/sh testuser && \
    echo "testuser:test" | chpasswd

# Configure SSH
RUN ssh-keygen -A && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    echo "Subsystem sftp /usr/lib/ssh/sftp-server" >> /etc/ssh/sshd_config

# Create test directories
RUN mkdir -p /home/testuser/uploads /home/testuser/downloads && \
    echo "Test file content for download" > /home/testuser/downloads/testfile.txt && \
    chown -R testuser:testuser /home/testuser

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
