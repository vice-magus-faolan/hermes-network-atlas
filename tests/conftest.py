# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared pytest scratch and network-free fixture policy."""
import pytest

import helpers
from network_guard import deny_network

# Also covers collection-time imports. Child-process fixtures install their own
# tripwire; --network none provides OS-level isolation for the Docker suite.
deny_network()


@pytest.fixture(autouse=True)
def synthetic_scratch(tmp_path, monkeypatch):
    """Keep legacy unittest fixture homes within ordinary pytest-owned scratch."""
    monkeypatch.setattr(helpers, "SCRATCH_ROOT", tmp_path)
