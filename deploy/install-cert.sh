#!/bin/sh
# Copy the relay's certificate from certbot's folders (root only) to
# deploy/tls/, readable by the relay's user, and tell the relay to re-read
# it. Run after `certbot certonly` and after every `certbot renew`
# (certbot's --deploy-hook can call it).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
name=${1:-relay.cloudmorrow.com}
live=/etc/letsencrypt/live/$name
mkdir -p "$here/tls"
install -m 0644 -o 10001 "$live/fullchain.pem" "$here/tls/fullchain.pem"
install -m 0600 -o 10001 "$live/privkey.pem" "$here/tls/privkey.pem"
docker compose -f "$here/docker-compose.yml" kill -s HUP relay
