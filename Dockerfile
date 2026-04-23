# Docker Hardened Image: signed by Anchore/Docker, continuously rebuilt on
# CVE disclosure, ships with an SBOM. The `-sfw-dev` variant adds Socket
# Firewall Free — during `pip install` below, every package (direct +
# transitive) is checked against Socket's malicious-package feed and blocked
# before it lands on disk. Build-time only; no runtime overhead or config.
FROM dhi.io/python:3-sfw-dev

# DHI base images run as a non-root user by default. The gateway needs
# CAP_NET_ADMIN to manipulate wg0 + iptables, so we must run as root in
# the container. cap_drop:ALL + cap_add:NET_ADMIN + no-new-privileges in
# docker-compose.yml keep the blast radius narrow.
USER root

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      wireguard-tools \
      iptables \
      iproute2 \
      conntrack \
      ca-certificates \
      tini \
      tzdata \
 && rm -rf /var/lib/apt/lists/*

# Default timezone; override via `TZ` env in docker-compose.yml.
ENV TZ=Europe/Zurich

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py wsgi.py gateway.py wg.py audit.py webhooks.py hash_password.py entrypoint.sh gunicorn.conf.py ./
COPY templates ./templates
COPY static ./static
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
EXPOSE 51820/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
