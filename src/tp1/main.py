import argparse
import json

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """
    Lecture des arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(description="TP1 - IDS/IPS maison")
    parser.add_argument("--pcap", default="", help="fichier pcap a analyser")
    parser.add_argument("--out", default="report.json", help="fichier JSON de sortie")
    return parser.parse_args(args)


def main() -> None:
    args = parse_args()
    logger.info("Starting TP1")

    # Sans --pcap, l'outil capture le trafic en direct sur une interface
    capture = Capture(args.pcap)
    capture.capture_traffic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    # Ecriture du rapport JSON en premier pour la correction automatique
    result = {
        "protocols": capture.protocols,
        "attacks": capture.get_json_attacks(),
        "flag": capture.flag,
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    logger.info(f"Rapport JSON genere : {args.out}")

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
