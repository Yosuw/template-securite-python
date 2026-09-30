from unittest.mock import patch

from src.tp1.main import main, parse_args


def test_parse_args():
    # When
    args = parse_args(["--pcap", "capture.pcap", "--out", "resultat.json"])

    # Then
    assert args.pcap == "capture.pcap"
    assert args.out == "resultat.json"


def test_parse_args_default_values():
    # When
    args = parse_args([])

    # Then
    assert args.pcap == ""
    assert args.out == "report.json"


def test_main(tmp_path):
    # Given
    out = str(tmp_path / "report.json")

    # When
    # On simule la capture et le rapport pour tester seulement l'enchainement
    with (
        patch("src.tp1.main.parse_args") as mock_args,
        patch("src.tp1.main.Capture") as mock_capture,
        patch("src.tp1.main.Report") as mock_report,
    ):
        mock_args.return_value.pcap = "capture.pcap"
        mock_args.return_value.out = out
        mock_capture.return_value.protocols = {"TCP": 1}
        mock_capture.return_value.get_json_attacks.return_value = []
        mock_capture.return_value.flag = None
        main()

    # Then
    mock_capture.assert_called_once_with("capture.pcap")
    mock_report.return_value.save.assert_called_once_with("report.pdf")
    with open(out) as f:
        assert '"TCP": 1' in f.read()
