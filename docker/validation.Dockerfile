# SPDX-License-Identifier: GPL-3.0-or-later
# Dependencies and native installer checks run online; Atlas checks run offline.
FROM python:3.14.7-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v0.22.2 https://github.com/NousResearch/hermes-agent.git /opt/hermes
COPY requirements-test.txt /opt/requirements-test.txt
# PM's frozen build uses the release's uv.lock and supported editable install.
# Native installer checks use these image-owned PM tools and cache inputs.
ENV HERMES_HOME=/opt/build-home HERMES_RUNTIME_DIR=/opt/atlas-runtime/tools
RUN cd /opt/hermes \
    && python3 -m pm.build_env --source /opt/hermes --out /opt/atlas-venv \
       --cache /opt/atlas-runtime/uv-cache \
    && python3 -m pip --python /opt/atlas-venv install --disable-pip-version-check --no-cache-dir \
       -r /opt/requirements-test.txt \
    && useradd --create-home atlas \
    && mkdir /workspace && chown atlas:atlas /workspace \
    && chown -R atlas:atlas /opt/hermes /opt/atlas-runtime
# Only public source enters the image; no host homes, receipts or Docker socket.
COPY --chown=atlas:atlas . /workspace/network-atlas
USER atlas
WORKDIR /workspace/network-atlas
ENV HOME=/home/atlas HERMES_HOME=/home/atlas/hermes-test PYTHONDONTWRITEBYTECODE=1 \
    NETWORK_ATLAS_HERMES_ROOT=/opt/hermes PATH=/opt/atlas-venv/bin:$PATH
# Real fresh-home enablement resolves dependencies and therefore needs network.
# A failing installer assertion fails the ordinary image build, including CI.
RUN python3 -m pytest -q -rP tests/test_compatibility.py
CMD ["sh", "-ec", "hermes --version && hermes plugins validate . && hermes plugins doctor . --ci && python3 -m pytest -q -rP --ignore=tests/test_compatibility.py"]
