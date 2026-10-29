"""Lancement du TP3 : partie Web puis partie réseau."""

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

logger = logging.getLogger("tp3.main")


class ChallengeError(RuntimeError):
    """Erreur pendant la résolution du challenge."""


def breach_web(target: str) -> tuple[str, ConnectionInfo]:
    """Trouver la page cachée et récupérer les informations TCP."""

    with requests.Session() as session:

        pages = [fetch(session, target), *fuzz(session, target)]

        for response in pages:

            try:
                content = try_captcha(session, response)

            except (CaptchaError, HttpError) as error:
                logger.warning("CAPTCHA non résolu : %s", error)
                continue

            flag = extract_flag(content)  # Cherche le premier flag

            if flag is None:
                continue

            try:
                info = parse_connection(content)

            except ParsingError as error:
                raise ChallengeError(str(error)) from error

            return flag, info

    raise ChallengeError("Flag1 ou paramètres TCP non trouvés")


def main() -> int:
    """Lancer les étapes du TP3."""

    setup_logging()

    parser = argparse.ArgumentParser(
        description="TP3 : Web puis réseau"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Adresse Web de la cible",
    )

    args = parser.parse_args()

    try:
        flag, connection = breach_web(args.target)

        print(f"[+] FLAG1: {flag}", flush=True)  # Affiche le premier flag

        final = breach_network(connection)

        print(f"[+] FLAG_FINAL: {final}", flush=True)  # Affiche le flag final

    except (
        HttpError,
        CaptchaError,
        ChallengeError,
        ProtocolError,
    ) as error:

        logger.error("[-] %s", error)

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())