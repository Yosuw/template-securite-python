import sys

from src.tp2.utils.binary import find_suspicious_apis, parse_binary


def test_parse_binary_with_real_binary():
    # On analyse l'executable Python lui-meme, qui est un vrai binaire
    result = parse_binary(sys.executable)

    assert result["format"] in ("ELF", "PE", "MACHO")
    assert len(result["sections"]) > 0
    assert "entropy" in result["sections"][0]


def test_parse_binary_with_overlay(tmp_path):
    # Given : un vrai binaire avec des donnees ajoutees a la fin
    with open(sys.executable, "rb") as f:
        data = f.read()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(data + b"--- donnees cachees ---")

    # When
    result = parse_binary(str(sample))

    # Then
    assert result["overlay"] == b"--- donnees cachees ---"


def test_parse_binary_with_text_file(tmp_path):
    # Un fichier texte n'est pas un binaire
    sample = tmp_path / "note.txt"
    sample.write_text("simple texte")

    result = parse_binary(str(sample))

    assert result["format"] is None
    assert result["overlay"] == b""


def test_find_suspicious_apis():
    names = ["printf", "connect", "WinExec", "malloc", "connect"]
    assert find_suspicious_apis(names) == ["WinExec", "connect"]
