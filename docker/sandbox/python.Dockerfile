# Sandbox image for Python repos: python:3.12-slim + git + grype (checksum-verified, vulnerability DB baked in).
# Rebuild regularly (CI, daily) so the baked grype DB stays fresh: the sandbox runs with the DB auto-update off.
FROM python:3.12-slim

ARG GRYPE_VERSION=0.120.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    base="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}"; \
    tarball="grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"; \
    curl -fsSL -o "/tmp/${tarball}" "${base}/${tarball}"; \
    curl -fsSL -o /tmp/checksums.txt "${base}/grype_${GRYPE_VERSION}_checksums.txt"; \
    (cd /tmp && grep " ${tarball}\$" checksums.txt | sha256sum -c -); \
    tar -xzf "/tmp/${tarball}" -C /usr/local/bin grype; \
    rm -f /tmp/grype_* /tmp/checksums.txt

RUN useradd --uid 1000 --create-home --shell /bin/bash sandbox \
    && mkdir -p /workspace /opt/venv /grype-db \
    && chown 1000:1000 /workspace /opt/venv /grype-db

USER sandbox
ENV GRYPE_DB_CACHE_DIR=/grype-db \
    GRYPE_CHECK_FOR_APP_UPDATE=false
RUN grype db update

ENV GRYPE_DB_AUTO_UPDATE=false \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp
WORKDIR /workspace
CMD ["sleep", "infinity"]
