"""Lancement du TP3 : découverte HTTP puis résolution réseau."""

import argparse
import logging

import requests

from tp3.utils.captcha import CaptchaError
from tp3.utils.http import HttpError, fetch, fuzz, try_captcha
from tp3.utils.logger import setup_logging
from tp3.utils.parsing import (
    ConnectionInfo,
    ParsingError,
    extract_flag,
    parse_connection,
)
from tp3.utils.protocol import ProtocolError, breach_network

logger = logging.getLogger(__name__)


class ChallengeError(RuntimeError):
    """Les données nécessaires au TP3 sont introuvables."""


def breach_web(target: str) -> tuple[str, ConnectionInfo]:
    """Chercher le premier flag et les informations du service TCP."""
    with requests.Session() as session:
        pages = [fetch(session, target), *fuzz(session, target)]  # Pages trouvées
        flag = None
        info = None
        for response in pages:
            content = response.text
            try:
                content = try_captcha(session, response)
            except (CaptchaError, HttpError) as error:
                logger.debug("CAPTCHA ignoré : %s", error)
            flag = flag or extract_flag(content)  # Cherche le premier flag
            try:
                info = parse_connection(content)
            except ParsingError:
                continue
            if flag and info:
                break
        if info is None or flag is None:
            raise ChallengeError("Flag1 ou paramètres TCP non trouvés")
        return flag, info


def main() -> int:
    """Lire --target, exécuter la chaîne et journaliser les flags."""
    setup_logging()
    parser = argparse.ArgumentParser(description="Solveur du TP3 ESGI")
    parser.add_argument("--target", required=True, help="URL HTTP du conteneur")
    args = parser.parse_args()
    try:
        flag1, connection = breach_web(args.target)
        logger.info("[+] FLAG1: %s", flag1)
        final = breach_network(connection)  # Passe à la partie TCP
        logger.info("[+] FLAG_FINAL: %s", final)
    except (HttpError, ChallengeError, ProtocolError) as error:
        logger.error("[-] %s", error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
