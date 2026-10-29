"""Tests des appels HTTP et de la wordlist."""

from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
from _pytest.monkeypatch import MonkeyPatch

from tp3.utils.http import HttpError, fetch, fuzz, try_captcha


def test_fetch() -> None:
    """Contrôler l'URL demandée et le timeout."""
    session = Mock()
    response = Mock()
    session.get.return_value = response
    assert fetch(session, "http://local/") is response
    session.get.assert_called_once_with("http://local/", timeout=4)


def test_fetch_error() -> None:
    """Convertir une exception requests en erreur HTTP dédiée."""
    session = Mock()
    session.get.side_effect = requests.ConnectionError("down")
    with pytest.raises(HttpError):
        fetch(session, "http://local/")


def test_fuzz(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Retenir les chemins dont la réponse n'est pas 404."""
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("missing\nsecret\n", encoding="utf-8")
    monkeypatch.setattr("tp3.utils.http.WORDLIST", wordlist)
    session = Mock()
    session.get.side_effect = [Mock(status_code=404), Mock(status_code=200)]
    found = fuzz(session, "http://local")
    assert len(found) == 1


def test_try_captcha_without_form() -> None:
    """Conserver la page lorsqu'aucun CAPTCHA n'existe."""
    response = Mock(text="hello", url="http://local/")
    assert try_captcha(Mock(), response) == "hello"
