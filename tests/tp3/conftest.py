"""Fixtures pytest utilisées pour les tests TP3."""

import pytest

from tp3.utils.parsing import ConnectionInfo


@pytest.fixture
def connection() -> ConnectionInfo:
    """Fournir des paramètres TCP fictifs."""
    return ConnectionInfo("127.0.0.1", 4444, b"B")
