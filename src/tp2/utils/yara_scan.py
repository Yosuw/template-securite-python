from pathlib import Path

import yara

from tp2.utils.config import logger

# Nos regles sont ecrites ici et pas dans des fichiers .yar,
# car le depot ne garde pas les fichiers .yar
BUILTIN_RULES = r"""
rule Suspicious_Downloader
{
    meta:
        description = "Telecharge un fichier depuis internet (adaptee du cours)"
    strings:
        $a = "urlmon.dll" nocase
        $b = "URLDownloadToFile" nocase
        $c = "WinExec" nocase
    condition:
        2 of them
}

rule Has_Mutex
{
    meta:
        description = "Cree un mutex nomme pour ne s'executer qu'une fois"
    strings:
        $mutex = /(Global|Local)\\[A-Za-z0-9_.-]{4,}/
    condition:
        $mutex
}

rule Prompt_Injection_Attempt
{
    meta:
        description = "Texte qui essaie de manipuler une IA qui analyse le fichier"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "ignore all previous" nocase
        $c = "AI_INSTRUCTIONS" nocase
        $d = "NOTE_TO_AI" nocase
    condition:
        any of them
}
"""


def load_rules(rules_dir: str | None) -> list:
    """
    Compile nos regles et toutes les regles .yar/.yara du dossier donne
    """
    compiled = [yara.compile(source=BUILTIN_RULES)]
    if rules_dir:
        for path in sorted(Path(rules_dir).glob("*.yar*")):
            # Chaque fichier est compile a part : un fichier invalide ne bloque pas les autres
            try:
                compiled.append(yara.compile(filepath=str(path)))
            except yara.Error as error:
                logger.warning(f"Regle YARA ignoree ({path.name}) : {error}")
    return compiled


def yara_scan(data: bytes, rules: list) -> list[str]:
    """
    Retourne les noms des regles YARA qui correspondent aux donnees
    """
    matches = set()
    for compiled in rules:
        for match in compiled.match(data=data):
            matches.add(match.rule)
    return sorted(matches)
