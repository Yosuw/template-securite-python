from tp2.utils.binary import find_suspicious_apis, parse_binary
from tp2.utils.config import logger
from tp2.utils.iocs import extract_flag, extract_iocs, extract_strings
from tp2.utils.llm import SYSTEM_PROMPT, LLMClient, build_prompt, parse_llm_response
from tp2.utils.metadata import get_file_metadata, shannon_entropy
from tp2.utils.verdict import combine_verdicts, deterministic_verdict, is_packed
from tp2.utils.yara_scan import yara_scan


def llm_triage(features: dict, client: LLMClient) -> dict | None:
    """
    Demande un verdict au LLM a partir du resume structure (jamais le binaire brut)
    """
    answer = client.ask(SYSTEM_PROMPT, build_prompt(features))
    verdict = parse_llm_response(answer)
    if answer and verdict is None:
        logger.warning("Reponse du LLM invalide, utilisation du verdict des regles")
    return verdict


class Triage:
    """
    Analyse complete d'un echantillon : metadonnees, binaire, IOC, YARA et verdict
    """

    def __init__(self, path: str, rules: list, client: LLMClient) -> None:
        self.path = path
        self.rules = rules
        self.client = client

    def run(self) -> dict:
        """
        Lance toutes les analyses et retourne le resultat au format du JSON attendu
        """
        logger.info(f"Analyse de {self.path}")
        with open(self.path, "rb") as f:
            data = f.read()

        metadata = get_file_metadata(data)
        binary = parse_binary(self.path)
        overlay = binary["overlay"]
        # S'il y a un overlay, la configuration du malware s'y trouve :
        # on y cherche les IOC pour ne pas confondre avec le code legitime du binaire
        suspicious_data = overlay or data

        iocs = extract_iocs(suspicious_data)
        apis = find_suspicious_apis(binary["imports"] + extract_strings(suspicious_data))
        features = {
            "file_type": metadata["file_type"],
            "entropy": metadata["entropy"],
            "packed": is_packed(metadata["entropy"], shannon_entropy(overlay), len(overlay)),
            "suspicious_apis": apis,
            "yara_matches": yara_scan(data, self.rules),
            "iocs": {key: iocs[key] for key in ("domains", "ips", "urls", "mutex", "registry")},
        }

        verdict = combine_verdicts(deterministic_verdict(features), llm_triage(features, self.client))

        return {
            "sha256": metadata["sha256"],
            "md5": metadata["md5"],
            "size": metadata["size"],
            "entropy": metadata["entropy"],
            "file_type": metadata["file_type"],
            "iocs": features["iocs"],
            "imports": apis,
            "yara_matches": features["yara_matches"],
            "family_guess": verdict["family"],
            "mitre_attack": verdict["mitre_attack"],
            "llm_summary": verdict["summary"],
            "score": verdict["score"],
            "flag": extract_flag(data),
        }
