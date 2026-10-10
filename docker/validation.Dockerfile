# SPDX-License-Identifier: GPL-3.0-or-later
# Stock Hermes and dependencies are acquired online; product checks run offline.
FROM python:3.14.7-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v0.21.6 https://github.com/NousResearch/hermes-agent.git /opt/hermes
COPY requirements-test.txt /opt/requirements-test.txt
RUN python3 -m pip install --disable-pip-version-check --no-cache-dir \
    -e /opt/hermes -r /opt/requirements-test.txt \
    && useradd --create-home atlas \
    && mkdir /workspace && chown atlas:atlas /workspace
# Only public source enters the image; no host homes, receipts or Docker socket.
COPY --chown=atlas:atlas . /workspace/network-atlas
USER atlas
WORKDIR /workspace/network-atlas
ENV HOME=/home/atlas HERMES_HOME=/home/atlas/hermes-test PYTHONDONTWRITEBYTECODE=1 \
    NETWORK_ATLAS_HERMES_ROOT=/opt/hermes
CMD ["sh", "-ec", "hermes plugins validate . && hermes plugins doctor . --ci && python3 -m pytest -q"]
