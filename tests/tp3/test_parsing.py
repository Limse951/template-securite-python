"""Tests d'extraction des paramètres et des flags."""

import pytest

from tp3.utils.parsing import ParsingError, extract_flag, parse_connection


def test_extract_flag() -> None:
    """Lire un flag présent dans une phrase."""
    assert extract_flag("ok ESGI{abc_123} done") == "ESGI{abc_123}"
    assert extract_flag("absent") is None


def test_parse_connection() -> None:
    """Accepter les champs JSON avec une clé hexadécimale."""
    info = parse_connection('{"host":"localhost","port":4444,"key":"0x42"}')
    assert (info.host, info.port, info.key) == ("localhost", 4444, b"B")


def test_parse_connection_invalid() -> None:
    """Refuser les réponses dépourvues de clé."""
    with pytest.raises(ParsingError):
        parse_connection("host=localhost port=44")
