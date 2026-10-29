"""Configuration du journal du programme."""

import logging
import sys


def setup_logging() -> logging.Logger:
    """Configurer un logger TP3 de niveau INFO vers stdout."""
    logger = logging.getLogger("tp3")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger
