# SPDX-License-Identifier: GPL-3.0-or-later
# Real linux/amd64 manifest digest, not a floating tag or guessed pin.
FROM python:3.14.7-slim-bookworm@sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561
ARG BASE_KEY
LABEL org.network-atlas.acceptance.owner="network-atlas-docker-v1" \
      org.network-atlas.acceptance.base="${BASE_KEY}" \
      org.network-atlas.acceptance.hermes="f42f579cf8bac4918ac9599bece71618afadd846" \
      org.network-atlas.acceptance.upstream="sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561"
COPY hermes.tar base_setup.py dependencies.json /opt/inputs/
# Dependency acquisition only. No candidate code/tests or host profile in context.
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260919T000000Z bookworm main' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260919T000000Z bookworm-security main' > /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates && \
    python3 /opt/inputs/base_setup.py && \
    rm -rf /var/lib/apt/lists /opt/inputs /root/.cache
USER 1000:1000
WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8
# No entrypoint, VOLUME, daemon/socket, ports, native selection or candidate state.
