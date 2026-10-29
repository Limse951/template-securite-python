"""Tests du décodage et du client réseau."""

import base64
from unittest.mock import MagicMock, patch

import pytest

from tp3.utils.parsing import ConnectionInfo
from tp3.utils.protocol import ProtocolError, breach_network, decode_challenge


def test_decode_challenge() -> None:
    """Décoder Base64 puis XOR avec une clé cyclique."""
    cipher = bytes([ord("H") ^ 66, ord("i") ^ 66])
    assert decode_challenge(base64.b64encode(cipher), b"B") == b"Hi"


def test_decode_challenge_error() -> None:
    """Refuser les chaînes non conformes au Base64."""
    with pytest.raises(ProtocolError):
        decode_challenge(b"#$", b"B")


def test_breach_network(connection: ConnectionInfo) -> None:
    """Répondre à un défi et reconnaître le flag final."""
    encoded = base64.b64encode(bytes([ord("A") ^ 66]))
    socket_mock = MagicMock()
    socket_mock.recv.side_effect = [encoded + b"\n", b"ESGI{final}\n"]
    socket_mock.__enter__.return_value = socket_mock
    with patch(
        "tp3.utils.protocol.socket.create_connection", return_value=socket_mock
    ):
        result = breach_network(connection)
    assert result == "ESGI{final}"
    socket_mock.sendall.assert_called_once_with(b"A\n")
