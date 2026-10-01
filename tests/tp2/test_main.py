import json
from unittest.mock import patch

from src.tp2.main import main, parse_args


def test_parse_args():
    args = parse_args(["--samples", "s", "--rules", "r", "--out", "o"])
    assert (args.samples, args.rules, args.out) == ("s", "r", "o")


def test_parse_args_default_values():
    args = parse_args(["--samples", "s"])
    assert args.rules is None
    assert args.out == "out"


def test_main(tmp_path):
    # Given : un dossier avec un echantillon
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "a.bin").write_bytes(b"\x00evil.example.test\x00FLAG=ESGI{test}\x00")
    out = tmp_path / "out"

    # When : le LLM est injoignable
    with (
        patch("src.tp2.main.parse_args") as mock_args,
        patch("src.tp2.main.LLMClient") as mock_client,
    ):
        mock_args.return_value = parse_args(["--samples", str(samples), "--out", str(out)])
        mock_client.return_value.ask.return_value = None
        main()

    # Then : un fichier <sha256>.json a ete ecrit
    files = list(out.glob("*.json"))
    assert len(files) == 1
    result = json.loads(files[0].read_text())
    assert files[0].name == f"{result['sha256']}.json"
    assert result["flag"] == "ESGI{test}"
    assert result["iocs"]["domains"] == ["evil.example.test"]
