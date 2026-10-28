import base64
import binascii
import re
import socket
import time

from src.tp3.utils.config import logger

FLAG_RE = re.compile(rb"ESGI\{[^}]*\}")


def xor(data: bytes, key: bytes) -> bytes:
    """
    Applique un XOR entre les donnees et la cle repetee
    """
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class Network:
    """
    Phase reseau : decode les jetons (base64 puis XOR) en boucle jusqu'au flag final
    """

    def __init__(self, host: str, port: int, key: str, timeout: int = 30) -> None:
        """
        Prepare la connexion au service revele par la phase web
        """
        self.host = host
        self.port = int(port)
        self.key = bytes.fromhex(key)  # la cle est donnee en hexadecimal
        self.timeout = timeout
        self.flag = ""

    def process_line(self, line: bytes) -> tuple | None:
        """
        Analyse une ligne : flag final, jeton a decoder, ou ligne a ignorer
        """
        text = line.strip()
        if not text:
            return None
        match = FLAG_RE.search(text)
        if match:
            return ("flag", match.group().decode())
        try:
            # un jeton valide est du base64 ; les lignes d'instructions echouent ici
            token = xor(base64.b64decode(text, validate=True), self.key)
        except (binascii.Error, ValueError):
            return None
        return ("token", token)

    def run(self) -> str:
        """
        Se connecte, repond a chaque jeton et renvoie le flag final (avant la limite de temps)
        """
        deadline = time.time() + self.timeout
        with socket.create_connection((self.host, self.port), timeout=10) as sock:
            sock.settimeout(self.timeout)
            stream = sock.makefile("rwb")
            while time.time() < deadline:
                line = stream.readline()
                if not line:
                    break
                action = self.process_line(line)
                if action is None:
                    continue
                kind, value = action
                if kind == "flag":
                    self.flag = value
                    logger.info("flag final recupere")
                    return value
                stream.write(value + b"\n")
                stream.flush()
        raise RuntimeError("flag final non obtenu dans le temps imparti")
