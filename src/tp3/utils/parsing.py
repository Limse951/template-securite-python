"""Extraction du flag, de l'hôte, du port et de la clé XOR."""

import re
from dataclasses import dataclass


class ParsingError(ValueError):
    """Réponse serveur incomplète ou impossible à interpréter."""


@dataclass(frozen=True)
class ConnectionInfo:
    """Paramètres nécessaires pour rejoindre le service TCP."""

    host: str
    port: int
    key: bytes


def extract_flag(text: str) -> str | None:
    """Trouver un flag ESGI au milieu d'une réponse."""
    match = re.search(r"ESGI\{[^}\r\n]+\}", text)  # Repère le flag
    return match.group(0) if match else None


def _field(text: str, names: str) -> str | None:
    """Lire un champ JSON ou une ligne nom-valeur."""
    pattern = rf"[\"\']?(?:{names})[\"\']?\s*[:=]\s*[\"\']?([^\s,;\"\'<>}}]+)"
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1) if match else None


def parse_connection(text: str) -> ConnectionInfo:
    """Lire host/port/key dans du texte ou du JSON simple."""
    host = _field(text, r"host|hostname|tcp_host|server")
    port_text = _field(text, r"port|tcp_port")
    key_text = _field(text, r"key|xor_key|xor|secret")
    if not host or not port_text:
        address = re.search(r"([\w.\-]+):(\d{2,5})", text)
        if address:
            host, port_text = address.groups()
    if not host or not port_text or key_text is None:
        raise ParsingError("Host, port ou clé XOR manquants")
    try:
        port = int(port_text)  # Convertit le port en entier
    except ValueError as error:
        raise ParsingError("Port non numérique") from error
    if not 1 <= port <= 65535:
        raise ParsingError("Port hors limites")
    if key_text.lower().startswith("0x"):
        try:
            value = bytes.fromhex(key_text[2:])  # Lit la clé en hexadécimal
        except ValueError as error:
            raise ParsingError("Clé hexadécimale invalide") from error
    else:
        value = key_text.encode("utf-8")
    if not value:
        raise ParsingError("Clé XOR vide")
    return ConnectionInfo(host, port, value)
