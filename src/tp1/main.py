import json

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    # Ecriture du rapport JSON pour la correction automatique
    result = {
        "protocols": capture.protocols,
        "attacks": capture.attacks,
        "flag": capture.flag,
    }
    with open("report.json", "w") as f:
        json.dump(result, f, indent=2)
    logger.info("Rapport JSON genere : report.json")


if __name__ == "__main__":
    main()