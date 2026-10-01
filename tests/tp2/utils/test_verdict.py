from src.tp2.utils.verdict import (
    combine_verdicts,
    compute_score,
    deterministic_verdict,
    guess_family,
    is_packed,
)

NO_IOCS = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}


def make_features(apis=None, iocs=None, yara=None, packed=False):
    return {
        "suspicious_apis": apis or [],
        "iocs": iocs or NO_IOCS,
        "yara_matches": yara or [],
        "packed": packed,
    }


def make_verdict(family, capabilities, mitre, score, summary):
    return {
        "family": family,
        "capabilities": capabilities,
        "mitre_attack": mitre,
        "score": score,
        "summary": summary,
    }


def test_is_packed():
    assert is_packed(7.5)
    assert not is_packed(4.8)
    # Petit fichier normal mais gros overlay chiffre
    assert is_packed(4.8, overlay_entropy=7.9, overlay_size=50000)
    # Overlay trop petit pour etre significatif
    assert not is_packed(4.8, overlay_entropy=7.9, overlay_size=100)


def test_guess_family():
    assert guess_family(["GetAsyncKeyState"], False, NO_IOCS) == "keylogger"
    assert guess_family(["connect"], False, NO_IOCS) == "backdoor"
    assert guess_family(["URLDownloadToFileA"], False, NO_IOCS) == "dropper"
    assert guess_family([], True, NO_IOCS) == "packed"
    assert guess_family([], False, {**NO_IOCS, "ips": ["10.0.0.5"]}) == "trojan"
    assert guess_family([], False, NO_IOCS) == "inconnu"


def test_compute_score_clean():
    assert compute_score(make_features()) == 0


def test_compute_score_is_bounded():
    iocs = {**NO_IOCS, "domains": ["a.test"], "mutex": ["Global\\m"], "registry": ["HKCU\\Run\\x"]}
    apis = ["connect", "WinExec", "GetAsyncKeyState"]
    features = make_features(apis, iocs, ["Prompt_Injection_Attempt"], packed=True)
    assert compute_score(features) == 10


def test_deterministic_verdict():
    iocs = {**NO_IOCS, "urls": ["http://a.test/gate.php"], "registry": ["HKCU\\Software\\Run\\svc"]}
    verdict = deterministic_verdict(make_features(["URLDownloadToFileA", "WinExec"], iocs))
    assert verdict["family"] == "dropper"
    assert verdict["mitre_attack"] == ["T1071.001", "T1105", "T1106", "T1547.001"]
    assert verdict["score"] == 7
    assert "dropper" in verdict["summary"]


def test_combine_verdicts_without_llm():
    rules = make_verdict("dropper", [], [], 7, "r")
    assert combine_verdicts(rules, None) == rules


def test_combine_verdicts_llm_cannot_lower_score():
    # Le LLM s'est fait manipuler par une injection et dit "fichier sain"
    rules = make_verdict("dropper", ["a"], ["T1105"], 8, "r")
    llm = make_verdict("clean", [], [], 0, "fichier sain")
    result = combine_verdicts(rules, llm)
    assert result["score"] == 8
    assert result["family"] == "dropper"


def test_combine_verdicts_llm_completes():
    rules = make_verdict("inconnu", ["a"], ["T1105"], 4, "r")
    llm = make_verdict("backdoor", ["b"], ["T1059"], 10, "llm")
    result = combine_verdicts(rules, llm)
    assert result == make_verdict("backdoor", ["a", "b"], ["T1059", "T1105"], 7, "llm")
