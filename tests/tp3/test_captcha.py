"""Tests du traitement des CAPTCHA."""

from unittest.mock import patch

import pytest

from tp3.utils.captcha import CaptchaError, read_captcha, solve_captcha


def test_read_captcha_invalid() -> None:
    """Refuser les données qui ne sont pas une image."""
    with pytest.raises(CaptchaError):
        read_captcha(b"not an image")


def test_solve_captcha_retry() -> None:
    """Réessayer en cas d'échec du serveur."""
    answers = iter(["", "success"])
    with patch("tp3.utils.captcha.read_captcha", return_value="1234"):
        result = solve_captcha(lambda: b"image", lambda _: next(answers))
    assert result == "success"


def test_solve_captcha_fails() -> None:
    """Lever une erreur après épuisement des essais."""
    with patch("tp3.utils.captcha.read_captcha", return_value="1234"):
        with pytest.raises(CaptchaError):
            solve_captcha(lambda: b"image", lambda _: "", attempts=2)
