#!/usr/bin/env bash

[[ -n ${ADMIN_USER} ]] || ADMIN_USER='admin'
[[ -n ${ADMIN_PASS} ]] || ADMIN_PASS='admin'

[[ -e /data/web-admin.certificate.pem ]] || openssl req -x509 -nodes -days 7300 -newkey rsa:4096 -keyout /data/web-admin.key.pem -out /data/web-admin.certificate.pem -subj "/C=PE/ST=Lima/L=Lima/O=Acme Inc. /OU=IT Department/CN=acme.com"

password_hash=$(echo -n "${ADMIN_PASS}" | warpgate hash | cat)

cat << EOF > /etc/warpgate.yaml
---
targets:
  - name: web-admin
    allow_roles:
      - "warpgate:admin"
    web_admin: {}
users:
  - username: ${ADMIN_USER}
    credentials:
      - type: password
        hash: "${password_hash}"
    roles:
      - "warpgate:admin"
roles:
  - name: "warpgate:admin"
recordings:
  enable: true
  path: /data/recordings
web_admin:
  enable: true
  listen: "0.0.0.0:8888"
  certificate: /data/web-admin.certificate.pem
  key: /data/web-admin.key.pem
database_url: "sqlite:/data/db"
ssh:
  listen: "0.0.0.0:2222"
  keys: /data/ssh-keys
  client_key: "./client_key"
retention: 7days
EOF

warpgate -c /etc/warpgate.yaml $@
