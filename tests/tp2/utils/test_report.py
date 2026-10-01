from src.tp2.utils.report import clean_text, generate_report

RESULT = {
    "sha256": "a" * 64,
    "md5": "b" * 32,
    "size": 1234,
    "entropy": 4.8,
    "file_type": "ELF 64-bit",
    "iocs": {"domains": ["evil.example.test"], "ips": [], "urls": [], "mutex": [], "registry": []},
    "imports": ["WinExec"],
    "yara_matches": ["Has_Mutex"],
    "family_guess": "dropper",
    "mitre_attack": ["T1105"],
    "llm_summary": "Resume avec des caracteres speciaux : é → 🚨",
    "score": 8,
    "flag": None,
}


def test_clean_text():
    # Les accents latins sont gardes, les autres caracteres sont remplaces
    assert clean_text("é → x") == "é ? x"


def test_generate_report(tmp_path):
    path = tmp_path / "rapport.pdf"
    generate_report(RESULT, str(path))
    # Un vrai fichier PDF commence toujours par %PDF
    assert path.read_bytes()[:4] == b"%PDF"
