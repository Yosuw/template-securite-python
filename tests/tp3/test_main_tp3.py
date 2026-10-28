from unittest.mock import MagicMock, patch

from src.tp3.main import main, parse_args, resolve_host


def test_parse_args():
    args = parse_args(["--target", "http://cible:8080"])
    assert args.target == "http://cible:8080"


def test_resolve_host_loopback():
    # pivot local -> on prend l'hote de la cible
    assert resolve_host("http://10.0.0.5:8080", "127.0.0.1") == "10.0.0.5"


def test_resolve_host_public():
    # pivot deja public -> on le garde
    assert resolve_host("http://10.0.0.5:8080", "203.0.113.9") == "203.0.113.9"


def test_main_affiche_les_deux_flags(caplog):
    pivot = {"flag1": "ESGI{web}", "host": "127.0.0.1", "port": 9090, "key": "ff193b22"}
    with (
        patch("src.tp3.main.parse_args") as mock_args,
        patch("src.tp3.main.Session") as mock_session,
        patch("src.tp3.main.Network") as mock_network,
        caplog.at_level("INFO"),
    ):
        mock_args.return_value = MagicMock(target="http://cible:8080")
        mock_session.return_value.run.return_value = pivot
        mock_network.return_value.run.return_value = "ESGI{chain}"
        main()

    assert "[+] FLAG1: ESGI{web}" in caplog.text
    assert "[+] FLAG_FINAL: ESGI{chain}" in caplog.text
    # le pivot local a ete remplace par l'hote de la cible
    mock_network.assert_called_once_with("cible", 9090, "ff193b22")
