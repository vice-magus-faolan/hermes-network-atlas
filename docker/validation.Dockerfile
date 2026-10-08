# SPDX-License-Identifier: GPL-3.0-or-later
# Ordinary disposable hosted provisioning; no retained producer or docker commit.
FROM python:3.14.7-slim-bookworm@sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git openssh-client build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-test.txt /opt/requirements-test.txt
RUN python3 -m pip install --disable-pip-version-check --no-cache-dir \
    --index-url https://pypi.org/simple -r /opt/requirements-test.txt \
    && useradd --uid 1000 --create-home atlas \
    && mkdir /state && chown 1000:1000 /state
# Hosted checkouts contain full committed trees and self-contained Git metadata.
# No home, credentials, daemon socket, preselected runtime or host bind mount.
COPY --chown=1000:1000 . /workspace/network-atlas
USER 1000:1000
WORKDIR /workspace/network-atlas
ENV HOME=/home/atlas TMPDIR=/state PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 \
    NETWORK_ATLAS_HERMES_ROOT=/workspace/network-atlas/.hermes-runtime-source
ENTRYPOINT ["python3", "scripts/disposable_validation.py"]
