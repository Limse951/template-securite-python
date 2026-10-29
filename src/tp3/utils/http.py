"""Découverte HTTP avec session et reconnaissance des formulaires."""

import logging
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag

from tp3.utils.captcha import solve_captcha
from tp3.utils.parsing import extract_flag

logger = logging.getLogger(__name__)
WORDLIST = Path(__file__).parent / "wordlist.txt"


class HttpError(RuntimeError):
    """Échec d'une interaction avec la cible HTTP."""


def fetch(session: requests.Session, url: str) -> requests.Response:
    """Effectuer un GET en conservant les cookies."""
    try:
        return session.get(url, timeout=4)
    except requests.RequestException as error:
        raise HttpError(f"Requête impossible : {url}") from error


def fuzz(session: requests.Session, target: str) -> list[requests.Response]:
    """Tester chaque chemin de la wordlist et garder les réponses utiles."""
    found = []
    paths = WORDLIST.read_text(encoding="utf-8").splitlines()  # Lit la liste
    for path in paths:
        if not path or path.startswith("#"):
            continue
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = fetch(session, url)
        except HttpError as error:
            logger.debug("%s", error)
            continue
        if response.status_code not in (404, 410):  # Garde les pages trouvées
            logger.info("[+] Endpoint : %s (%s)", url, response.status_code)
            found.append(response)
    return found


def _form_fields(form: Tag) -> dict[str, str]:
    """Préparer les champs cachés et les valeurs des formulaires."""
    return {
        field["name"]: field.get("value", "")
        for field in form.select("input[name]")
    }


def try_captcha(session: requests.Session, response: requests.Response) -> str:
    """Résoudre le premier formulaire accompagné d'une image CAPTCHA."""
    soup = BeautifulSoup(response.text, "html.parser")
    for form in soup.select("form"):
        image = form.select_one("img[src]")
        if image is None:
            continue
        fields = _form_fields(form)  # Garde les champs du formulaire
        answer_field = next(
            (item["name"] for item in form.select("input[name]")
             if "captcha" in item["name"].lower()),
            None,
        )
        if not answer_field:
            continue
        image_url = urljoin(response.url, image["src"])
        form_url = urljoin(response.url, form.get("action", ""))

        def submit(answer: str) -> str:
            """Envoyer la saisie OCR en gardant les champs existants."""
            fields[answer_field] = answer
            try:
                if form.get("method", "get").lower() == "post":
                    result = session.post(form_url, data=fields, timeout=4)
                else:
                    result = session.get(form_url, params=fields, timeout=4)
            except requests.RequestException as error:
                raise HttpError("Soumission CAPTCHA impossible") from error
            if result.status_code >= 400:
                return ""
            if "captcha" in result.text.lower() and not extract_flag(result.text):
                return ""
            return result.text

        return solve_captcha(lambda: fetch(session, image_url).content, submit)
    return response.text
