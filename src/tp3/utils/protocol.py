"""Client TCP pour les défis Base64 suivis d'un XOR."""

import base64
import binascii
import logging
import socket
import time

from tp3.utils.parsing import ConnectionInfo, extract_flag

logger = logging.getLogger(__name__)


class ProtocolError(RuntimeError):
    """Erreur de décodage, de communication ou de délai TCP."""


def decode_challenge(chunk: bytes, key: bytes) -> bytes:
    """Décoder Base64 puis appliquer la clé XOR cycliquement."""
    if not key:
        raise ProtocolError("Clé XOR vide")
    try:
        raw = base64.b64decode(chunk.strip(), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProtocolError("Défi Base64 invalide") from error
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(raw))


def breach_network(info: ConnectionInfo, limit: float = 30.0) -> str:
    """Répondre ligne par ligne aux défis jusqu'au flag ou au délai."""
    end = time.monotonic() + limit  # Limite de temps du défi
    buffer = b""
    try:
        with socket.create_connection((info.host, info.port), timeout=4) as conn:
            conn.settimeout(4)  # Délai de 4 secondes
            while time.monotonic() < end:
                chunk = conn.recv(4096)  # Récupère les données
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    text = line.decode("utf-8", errors="replace")
                    flag = extract_flag(text)
                    if flag:
                        return flag
                    if not line.strip():
                        continue
                    payload = line.split(b":", 1)[-1].strip()
                    try:
                        reply = decode_challenge(payload, info.key)
                    except ProtocolError:
                        logger.debug("Ligne TCP non décodable : %s", text)
                        continue
                    conn.sendall(reply + b"\n")  # Envoie la réponse
    except (socket.timeout, OSError) as error:
        raise ProtocolError("Connexion TCP échouée") from error
    raise ProtocolError("Flag final non reçu")
