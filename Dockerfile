# The relay, the control API and the DNS server: one process, one image.
FROM python:3.12-slim

RUN useradd --system --uid 10001 --home /var/lib/cloudmorrow-relay relay \
 && mkdir -p /var/lib/cloudmorrow-relay /etc/cloudmorrow-relay \
 && chown relay /var/lib/cloudmorrow-relay

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /src

# Ports below 1024 without root: Docker opens them to unprivileged users
# in the container's own network namespace, and with host networking the
# capability below does it.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && setcap cap_net_bind_service=+ep "$(readlink -f "$(which python3)")" \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

USER relay
WORKDIR /var/lib/cloudmorrow-relay
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp
ENTRYPOINT ["cloudmorrow-relay"]
CMD ["serve", "--config", "/etc/cloudmorrow-relay/relay.toml"]
