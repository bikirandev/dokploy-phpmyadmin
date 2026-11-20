# Test-only SSH bastion: user "deploy" with a key (from the fixtures) and a password.
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh deploy \
 && echo 'deploy:BastionPass-2026!' | chpasswd
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
