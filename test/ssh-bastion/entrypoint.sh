#!/bin/sh
set -eu
mkdir -p /home/deploy/.ssh
cp /fixtures/authorized_key.pub /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh
chmod 0700 /home/deploy/.ssh
chmod 0600 /home/deploy/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
