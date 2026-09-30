import pytest
from unittest.mock import patch
from scapy.all import Ether, IP, TCP, ARP, Raw
from src.tp1.utils.capture import Capture


@pytest.fixture(autouse=True)
def mock_interface():
    # Evite de demander une interface a l'utilisateur pendant les tests
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0"):
        yield


def fake_packets():
    # Paquets construits a la main pour les tests
    return [
        Ether() / IP() / TCP(),
        Ether() / IP() / TCP() / Raw(b"test"),
        Ether() / ARP(),
    ]


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == "eth0"
    assert capture.summary == ""
    assert capture.packets == []
    assert capture.protocols == {}
    assert capture.attacks == []


def test_given_capture_when_capture_traffic_then_packets_are_stored():
    # Given
    capture = Capture()

    # When
    # On simule sniff pour ne pas faire une vraie capture pendant les tests
    with patch("src.tp1.utils.capture.sniff", return_value=["pkt1", "pkt2"]) as mock_sniff:
        capture.capture_traffic()

    # Then
    mock_sniff.assert_called_once_with(iface="eth0", timeout=60)
    assert capture.packets == ["pkt1", "pkt2"]


def test_get_all_protocols_without_packets():
    # Given
    capture = Capture()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {}


def test_get_all_protocols():
    # Given
    capture = Capture()
    capture.packets = fake_packets()

    # When
    result = capture.get_all_protocols()

    # Then
    # Ether et Raw ne doivent pas etre comptes
    assert result == {"IP": 2, "TCP": 2, "ARP": 1}


def test_sort_network_protocols():
    # Given
    capture = Capture()
    capture.protocols = {"ARP": 1, "TCP": 5, "UDP": 3}

    # When
    result = capture.sort_network_protocols()

    # Then
    assert list(result.items()) == [("TCP", 5), ("UDP", 3), ("ARP", 1)]


def test_add_attack_without_duplicate():
    # Given
    capture = Capture()

    # When
    capture.add_attack("arp_spoofing", "ARP", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
    capture.add_attack("arp_spoofing", "ARP", "192.168.1.1", "aa:aa:aa:aa:aa:aa")

    # Then
    assert len(capture.attacks) == 1


def test_detect_arp_spoofing():
    # Given
    capture = Capture()
    capture.packets = [
        # Reponse legitime du routeur
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11"),
        # L'attaquant annonce la meme IP avec sa propre MAC
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff"),
    ]

    # When
    capture.detect_arp_spoofing()

    # Then
    assert capture.attacks == [
        {"type": "arp_spoofing", "protocol": "ARP", "ip": "192.168.1.1", "attacker": "aa:bb:cc:dd:ee:ff"}
    ]


def test_detect_arp_spoofing_with_legitimate_traffic():
    # Given
    capture = Capture()
    capture.packets = [
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11"),
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11"),
    ]

    # When
    capture.detect_arp_spoofing()

    # Then
    assert capture.attacks == []


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string