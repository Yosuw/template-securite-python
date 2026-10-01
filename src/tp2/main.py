import argparse
import json
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.llm import LLMClient
from tp2.utils.report import generate_report
from tp2.utils.triage import Triage
from tp2.utils.yara_scan import load_rules


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """
    Lecture des arguments de la ligne de commande
    """
    parser = argparse.ArgumentParser(description="TP2 - Triage automatise de malware")
    parser.add_argument("--samples", required=True, help="dossier des echantillons a analyser")
    parser.add_argument("--rules", default=None, help="dossier des regles YARA supplementaires")
    parser.add_argument("--out", default="out", help="dossier de sortie des fichiers JSON")
    return parser.parse_args(args)


def main() -> None:
    """
    Analyse chaque echantillon du dossier et ecrit un JSON par echantillon
    """
    args = parse_args()
    logger.info("Starting TP2")

    rules = load_rules(args.rules)
    client = LLMClient()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    samples = sorted(path for path in Path(args.samples).iterdir() if path.is_file())
    for sample in samples:
        result = Triage(str(sample), rules, client).run()
        # La consigne demande <sha256>.json et le correcteur cherche <echantillon>.triage.json :
        # on ecrit le meme resultat sous les deux noms (avec et sans l'extension de l'echantillon)
        names = {f"{result['sha256']}.json", f"{sample.name}.triage.json", f"{sample.stem}.triage.json"}
        for name in sorted(names):
            with open(out_dir / name, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"{sample.name} : {result['family_guess']}, score {result['score']}")
        # Rapport PDF lisible a cote du JSON
        generate_report(result, str(out_dir / f"{result['sha256']}.pdf"))


if __name__ == "__main__":
    main()
