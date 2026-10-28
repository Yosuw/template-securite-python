import argparse
from urllib.parse import urlparse

from src.tp3.utils.config import logger
from src.tp3.utils.network import Network
from src.tp3.utils.session import Session

# adresses locales : sur l'instance hebergee, le service est en realite sur l'hote de la cible
LOOPBACK = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """
    Lecture des arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(description="TP3 - Breach the target")
    parser.add_argument("--target", required=True, help="URL de la cible, ex http://localhost:8080")
    return parser.parse_args(args)


def resolve_host(target: str, pivot_host: str) -> str:
    """
    Si le pivot indique une adresse locale, on vise plutot l'hote de la cible
    """
    if pivot_host in LOOPBACK:
        return urlparse(target).hostname or pivot_host
    return pivot_host


def main() -> None:
    """
    Enchaine la phase web puis la phase reseau et affiche les deux flags
    """
    args = parse_args()
    logger.info("Starting TP3")

    # Phase web : endpoint cache + captcha -> flag1 et pivot (host, port, key)
    pivot = Session(args.target).run()

    # Phase reseau : decodage en boucle sur le service revele -> flag final
    host = resolve_host(args.target, pivot["host"])
    flag_final = Network(host, pivot["port"], pivot["key"]).run()

    logger.info(f"[+] FLAG1: {pivot['flag1']}")
    logger.info(f"[+] FLAG_FINAL: {flag_final}")


if __name__ == "__main__":
    main()
