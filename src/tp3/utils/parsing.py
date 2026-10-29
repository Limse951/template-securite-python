"""Extraction des flags et des informations du serveur TCP."""

import json
import re
from dataclasses import dataclass


class ParsingError(ValueError):
    """Erreur pendant la lecture des informations."""


@dataclass(frozen=True)
class ConnectionInfo:
    """Informations pour se connecter au serveur TCP."""

    host: str
    port: int
    key: bytes


def extract_flag(text: str) -> str | None:
    """Chercher un flag ESGI dans une réponse."""

    match = re.search(r"ESGI\{[^}\r\n]+\}", text)

    return match.group(0) if match else None


def _field(text: str, names: str) -> str | None:
    """Récupérer la valeur d'un champ."""

    pattern = rf'["\']?(?:{names})["\']?\s*[:=]\s*["\']?([^\s,;"\'<>}}]+)'

    match = re.search(pattern, text, re.IGNORECASE)

    return match.group(1) if match else None


def parse_connection(text: str) -> ConnectionInfo:
    """Récupérer l'adresse, le port et la clé XOR."""

    try:
        data = json.loads(text)

    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):

        host = data.get("host")
        port = data.get("port")
        key_text = data.get("key")

    else:

        host = _field(text, r"tcp_host|hostname|host|server")
        port = _field(text, r"tcp_port|port")
        key_text = _field(text, r"xor_key|key|xor|secret")

    if not host or port is None or not key_text:
        raise ParsingError("Hôte, port ou clé XOR manquants")

    try:
        port_number = int(port)  # Convertit le port en entier

    except (ValueError, TypeError) as error:
        raise ParsingError("Port TCP invalide") from error

    if not 1 <= port_number <= 65535:
        raise ParsingError("Port TCP hors limites")

    key_string = str(key_text)

    if key_string.lower().startswith("0x"):
        key_string = key_string[2:]

    try:
        key = bytes.fromhex(key_string)  # Convertit la clé hexadécimale

    except ValueError as error:
        raise ParsingError("Clé XOR hexadécimale invalide") from error

    if not key:
        raise ParsingError("Clé XOR vide")

    return ConnectionInfo(
        str(host),
        port_number,
        key,
    )