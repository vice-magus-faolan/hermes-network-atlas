# SPDX-License-Identifier: GPL-3.0-or-later
# Real linux/amd64 manifest digest, not a floating tag or guessed pin.
FROM python:3.14.7-slim-bookworm@sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561
LABEL org.network-atlas.acceptance.kind="declarative-upstream-anchor-not-a-base" \
      org.network-atlas.acceptance.hermes="5645275e50d66dca04c9565634f9b5207a38aef5" \
      org.network-atlas.acceptance.upstream="sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561"
# This is a reviewed identity anchor, NOT a Dockerfile build recipe/fallback.
# scripts/docker_builder.py owns public setup in one private root container,
# then commits only its stopped ordinary rootfs with exact nonroot readback.
# No dependency acquisition, source COPY, candidate code or native state here.
USER 1000:1000
WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8
# No entrypoint, VOLUME, daemon/socket, ports, native selection or candidate state.
