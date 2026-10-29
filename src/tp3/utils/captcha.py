"""Reconnaissance de CAPTCHA texte avec PIL et Tesseract."""

from collections.abc import Callable
from io import BytesIO

import pytesseract
from PIL import Image, ImageEnhance, ImageOps


class CaptchaError(RuntimeError):
    """Le CAPTCHA n'a pas pu être lu."""


def read_captcha(content: bytes) -> str:
    """Convertir une image en texte après amélioration du contraste."""
    try:
        image = Image.open(BytesIO(content)).convert("L")  # Niveaux de gris
        image = ImageOps.autocontrast(image)  # Améliore le contraste
        image = ImageEnhance.Contrast(image).enhance(2)
        image = image.point(lambda pixel: 255 if pixel > 145 else 0)
        text = pytesseract.image_to_string(image, config="--psm 7")
    except (OSError, pytesseract.TesseractError) as error:
        raise CaptchaError("Lecture OCR impossible") from error
    answer = "".join(char for char in text if char.isalnum())  # Nettoie le texte
    if not answer:
        raise CaptchaError("Aucun caractère reconnu")
    return answer


def solve_captcha(
    fetch_image: Callable[[], bytes],
    submit_answer: Callable[[str], str],
    attempts: int = 3,
) -> str:
    """Réessayer un CAPTCHA tant que le serveur refuse la réponse."""
    for _ in range(attempts):
        try:
            answer = read_captcha(fetch_image())
        except CaptchaError:
            continue
        response = submit_answer(answer)
        if response:
            return response
    raise CaptchaError("CAPTCHA non résolu après plusieurs essais")
