"""Shared fixtures."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otscope import scenarios  # noqa: E402
from otscope.analysis.engine import analyse_file  # noqa: E402


@pytest.fixture(scope="session")
def full_capture(tmp_path_factory) -> str:
    """A capture containing every scenario - the reference 'bad day'."""
    path = str(tmp_path_factory.mktemp("cap") / "all.pcap")
    scenarios.write_pcap(path)
    return path


@pytest.fixture(scope="session")
def full_report(full_capture):
    return analyse_file(full_capture)


def capture_of(tmp_path, names, name="one.pcap") -> str:
    path = str(tmp_path / name)
    scenarios.write_pcap(path, names)
    return path
