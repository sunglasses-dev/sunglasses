"""Pytest fixtures for SUNGLASSES test suite."""

import pytest
from sunglasses.engine import SunglassesEngine


@pytest.fixture
def engine():
    """Provide a SunglassesEngine instance for tests."""
    return SunglassesEngine()
