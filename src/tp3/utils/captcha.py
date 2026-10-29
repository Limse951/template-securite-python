"""Lecture des CAPTCHA avec Pillow et Tesseract."""

from collections.abc import Callable
from io import BytesIO

import pytesseract
from PIL import Image, ImageFilter, ImageOps


class CaptchaError(RuntimeError):
    """Erreur pendant la lecture du CAPTCHA."""


def read_captcha(content: bytes) -> str:
    """Lire les cinq caractères du CAPTCHA."""

    try:
        image = Image.open(BytesIO(content)).convert("L")  # Niveaux de gris

        image = ImageOps.autocontrast(image)

        image = image.filter(ImageFilter.MedianFilter(size=3))  # Enlève le bruit

        image = image.point(lambda value: 255 if value > 170 else 0)

        text = pytesseract.image_to_string(
            image,
            config=(
                "--psm 7 "
                "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            ),
        )

    except (
        OSError,
        pytesseract.TesseractError,
        pytesseract.TesseractNotFoundError,
    ) as error:
        raise CaptchaError("Impossible de lire le CAPTCHA") from error

    answer = "".join(
        char for char in text.upper() if char.isalnum()
    )

    if len(answer) != 5:
        raise CaptchaError("Le CAPTCHA doit contenir cinq caractères")

    return answer


def solve_captcha(
    fetch_image: Callable[[], bytes],
    submit_answer: Callable[[str], str],
    attempts: int = 6,
) -> str:
    """Réessayer jusqu'à obtenir une réponse valide."""

    for _ in range(attempts):

        try:
            answer = read_captcha(fetch_image())

        except CaptchaError:
            continue

        response = submit_answer(answer)

        if response:
            return response

    raise CaptchaError("Le serveur a refusé tous les CAPTCHA")