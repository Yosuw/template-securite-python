# Seuil d'entropie au dela duquel les donnees sont compressees ou chiffrees
PACKED_ENTROPY = 7.0

# Capacite et technique MITRE ATT&CK associees a chaque fonction suspecte
API_BEHAVIORS = {
    "URLDownloadToFileA": ("telechargement de fichier", "T1105"),
    "URLDownloadToFileW": ("telechargement de fichier", "T1105"),
    "WinExec": ("execution de programme", "T1106"),
    "ShellExecuteA": ("execution de programme", "T1106"),
    "CreateProcessA": ("execution de programme", "T1106"),
    "CreateProcessW": ("execution de programme", "T1106"),
    "WSASocketA": ("communication reseau", "T1095"),
    "connect": ("communication reseau", "T1095"),
    "SetWindowsHookExA": ("enregistrement du clavier", "T1056.001"),
    "SetWindowsHookExW": ("enregistrement du clavier", "T1056.001"),
    "GetAsyncKeyState": ("enregistrement du clavier", "T1056.001"),
    "VirtualAllocEx": ("injection de code", "T1055"),
    "WriteProcessMemory": ("injection de code", "T1055"),
    "CreateRemoteThread": ("injection de code", "T1055"),
}


def is_packed(entropy: float, overlay_entropy: float = 0.0, overlay_size: int = 0) -> bool:
    """
    Un fichier (ou un gros overlay) avec une entropie tres elevee est probablement packe
    """
    return entropy >= PACKED_ENTROPY or (overlay_size >= 1024 and overlay_entropy >= PACKED_ENTROPY)


def guess_family(apis: list[str], packed: bool, iocs: dict) -> str:
    """
    Devine la famille du malware a partir des fonctions suspectes
    """
    if {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"} & set(apis):
        return "keylogger"
    if {"WSASocketA", "connect"} & set(apis):
        return "backdoor"
    if {"URLDownloadToFileA", "URLDownloadToFileW"} & set(apis):
        return "dropper"
    if packed:
        return "packed"
    if any(iocs.get(key) for key in ("domains", "ips", "urls")):
        return "trojan"
    return "inconnu"


def compute_score(features: dict) -> int:
    """
    Score de dangerosite entre 0 et 10, calcule uniquement a partir des preuves
    """
    iocs = features["iocs"]
    score = 0
    score += min(4, 2 * len(features["suspicious_apis"]))
    score += 2 if (iocs["domains"] or iocs["ips"] or iocs["urls"]) else 0
    score += 1 if iocs["registry"] else 0
    score += 1 if iocs["mutex"] else 0
    score += 2 if features["packed"] else 0
    # Un fichier qui essaie de tromper l'analyse est suspect
    score += 1 if "Prompt_Injection_Attempt" in features["yara_matches"] else 0
    return min(10, score)


def deterministic_verdict(features: dict) -> dict:
    """
    Verdict calcule sans LLM : utilise quand le LLM est indisponible ou invalide
    """
    capabilities, techniques = set(), set()
    for api in features["suspicious_apis"]:
        if api in API_BEHAVIORS:
            capabilities.add(API_BEHAVIORS[api][0])
            techniques.add(API_BEHAVIORS[api][1])
    iocs = features["iocs"]
    if iocs["urls"] or iocs["domains"]:
        capabilities.add("communication avec un serveur C2")
        techniques.add("T1071.001")
    if any("\\Run" in key for key in iocs["registry"]):
        capabilities.add("persistance au demarrage")
        techniques.add("T1547.001")
    if features["packed"]:
        capabilities.add("code packe ou chiffre")
        techniques.add("T1027.002")

    family = guess_family(features["suspicious_apis"], features["packed"], iocs)
    score = compute_score(features)
    summary = f"Echantillon de type {family}, score {score}/10."
    if capabilities:
        summary += " Capacites : " + ", ".join(sorted(capabilities)) + "."
    return {
        "family": family,
        "capabilities": sorted(capabilities),
        "mitre_attack": sorted(techniques),
        "score": score,
        "summary": summary,
    }


def combine_verdicts(rules: dict, llm: dict | None) -> dict:
    """
    Combine le verdict des regles et celui du LLM.
    Le LLM ne decide jamais seul : il ne peut pas faire baisser le score des regles.
    """
    if llm is None:
        return rules
    return {
        "family": rules["family"] if rules["family"] != "inconnu" else llm["family"],
        "capabilities": sorted(set(rules["capabilities"]) | set(llm["capabilities"])),
        "mitre_attack": sorted(set(rules["mitre_attack"]) | set(llm["mitre_attack"])),
        "score": max(rules["score"], round((rules["score"] + llm["score"]) / 2)),
        "summary": llm["summary"] or rules["summary"],
    }
