"""Tests de configuration des logs."""

import logging

from tp3.utils.logger import setup_logging


def test_setup_logging() -> None:
    """Vérifier le niveau INFO et l'absence de doublons."""
    logger = setup_logging()
    count = len(logger.handlers)
    assert logger.level == logging.INFO
    assert logger.propagate is False
    assert len(setup_logging().handlers) == count
