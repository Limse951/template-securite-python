"""Gestion des requêtes HTTP, du fuzzing et du CAPTCHA."""

import logging
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag

from tp3.utils.captcha import solve_captcha

logger = logging.getLogger(__name__)

WORDLIST = Path(__file__).parent / "wordlist.txt"


class HttpError(RuntimeError):
    """Erreur pendant une requête HTTP."""


def fetch(session: requests.Session, url: str) -> requests.Response:
    """Envoyer une requête GET au serveur."""

    try:
        return session.get(url, timeout=4)

    except requests.RequestException as error:
        raise HttpError(f"Requête impossible : {url}") from error


def fuzz(session: requests.Session, target: str) -> list[requests.Response]:
    """Chercher les pages accessibles avec la wordlist."""

    found = []

    paths = WORDLIST.read_text(encoding="utf-8").splitlines()

    for path in paths:

        if not path or path.startswith("#"):
            continue

        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

        try:
            response = fetch(session, url)

        except HttpError as error:
            logger.debug("%s", error)
            continue

        if response.status_code not in (404, 410):

            logger.info(
                "[+] Endpoint : %s (%s)",
                url,
                response.status_code,
            )

            found.append(response)  # Garde la page trouvée

    return found


def _form_fields(form: Tag) -> dict[str, str]:
    """Récupérer les champs du formulaire."""

    return {
        field["name"]: field.get("value", "")
        for field in form.select("input[name]")
    }


def try_captcha(
    session: requests.Session,
    response: requests.Response,
) -> str:
    """Lire le CAPTCHA puis envoyer la réponse."""

    soup = BeautifulSoup(response.text, "html.parser")

    image = soup.select_one('img[src*="captcha"]')  # Cherche le CAPTCHA

    if image is None:
        return response.text

    for form in soup.select("form"):

        fields = _form_fields(form)

        answer_field = next(
            (
                field["name"]
                for field in form.select("input[name]")
                if "captcha" in field["name"].lower()
            ),
            None,
        )

        if answer_field is None:
            continue

        image_url = urljoin(response.url, image["src"])
        form_url = urljoin(response.url, form.get("action", ""))

        def get_image() -> bytes:
            """Récupérer une nouvelle image CAPTCHA."""

            fetch(session, response.url)  # Génère un nouveau code

            return fetch(session, image_url).content

        def submit(answer: str) -> str:
            """Envoyer le CAPTCHA au serveur."""

            fields[answer_field] = answer

            try:
                if form.get("method", "get").lower() == "post":

                    result = session.post(
                        form_url,
                        data=fields,
                        timeout=4,
                    )

                else:
                    result = session.get(
                        form_url,
                        params=fields,
                        timeout=4,
                    )

            except requests.RequestException as error:
                raise HttpError("Erreur pendant l'envoi") from error

            if result.status_code >= 400:
                return ""  # Réponse refusée

            return result.text

        return solve_captcha(
            get_image,
            submit,
            attempts=5,
        )

    return response.text