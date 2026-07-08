FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    WG_IFACE=wg0 \
    WG_DIR=/etc/wireguard \
    APP_PORT=8088

RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        iptables \
        iproute2 \
        iputils-ping \
        tcpdump \
        openresolv \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask gunicorn

WORKDIR /app
COPY app.py .version ./
COPY static ./static
COPY templates ./templates

COPY docker/systemctl docker/journalctl docker/sudo /usr/bin/
COPY docker/entrypoint.sh /entrypoint.sh
# /etc/sudoers.d must exist: the app installs a tc sudoers rule at runtime
# (meaningless in the container, but its absence logs errors)
RUN chmod +x /usr/bin/systemctl /usr/bin/journalctl /usr/bin/sudo /entrypoint.sh \
    && mkdir -p /etc/sudoers.d

EXPOSE 8088/tcp 51820/udp
VOLUME /etc/wireguard

ENTRYPOINT ["/entrypoint.sh"]
