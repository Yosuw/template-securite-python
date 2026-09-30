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
    assert capture.pcap == ""
    assert capture.summary == ""
    assert capture.packets == []
    assert capture.protocols == {}
    assert capture.attacks == []
    assert capture.flag is None


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

def test_capture_init_with_pcap():
    # When
    capture = Capture("test.pcap")

    # Then
    # Avec un fichier pcap, on ne demande pas d'interface
    assert capture.pcap == "test.pcap"
    assert capture.interface == ""


def test_given_pcap_when_capture_traffic_then_file_is_read():
    # Given
    capture = Capture("test.pcap")

    # When
    with patch("src.tp1.utils.capture.rdpcap", return_value=["pkt1"]) as mock_rdpcap:
        capture.capture_traffic()

    # Then
    mock_rdpcap.assert_called_once_with("test.pcap")
    assert capture.packets == ["pkt1"]


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
        # La victime demande la MAC du routeur
        Ether() / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1"),
        # Le vrai routeur repond a la demande
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11", pdst="192.168.1.10"),
        # L'attaquant envoie une reponse sans qu'on lui demande
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff", pdst="192.168.1.10"),
    ]

    # When
    capture.detect_arp_spoofing()

    # Then
    assert capture.attacks == [
        {"type": "arp_spoofing", "protocol": "ARP", "ip": "192.168.1.1", "attacker": "aa:bb:cc:dd:ee:ff"}
    ]


def test_detect_arp_spoofing_with_unordered_packets():
    # Given
    capture = Capture()
    request = Ether() / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1")
    request.time = 1
    legit = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11", pdst="192.168.1.10")
    legit.time = 2
    attack = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff", pdst="192.168.1.10")
    attack.time = 3
    # L'attaque apparait en premier dans le fichier, mais elle est la plus recente
    capture.packets = [attack, legit, request]

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


def test_detect_port_scan():
    # Given
    capture = Capture()
    # L'attaquant envoie un SYN sur 20 ports differents
    capture.packets = [
        Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.0.5") / TCP(dport=port, flags="S")
        for port in range(1, 21)
    ]

    # When
    capture.detect_syn_scan()

    # Then
    assert capture.attacks == [
        {"type": "port_scan", "protocol": "TCP", "ip": "10.0.0.5", "attacker": "aa:bb:cc:dd:ee:ff"}
    ]


def test_detect_syn_scan_with_legitimate_traffic():
    # Given
    capture = Capture()
    # Quelques connexions normales sur peu de ports
    capture.packets = [
        Ether(src="11:11:11:11:11:11") / IP(src="10.0.0.2") / TCP(dport=port, flags="S")
        for port in [80, 443, 22]
    ]

    # When
    capture.detect_syn_scan()

    # Then
    assert capture.attacks == []

def test_detect_sql_injection():
    # Given
    capture = Capture()
    # Requete HTTP avec une injection SQL encodee dans l'URL et le flag
    payload = b"GET /login?user=admin%27+or+1%3D1--&token=ESGI%7BTest_Flag%7D HTTP/1.1"
    capture.packets = [
        Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.0.5") / TCP(dport=80) / Raw(payload)
    ]

    # When
    capture.detect_sql_injection()

    # Then
    assert capture.attacks == [
        {"type": "sql_injection", "protocol": "TCP", "ip": "10.0.0.5", "attacker": "aa:bb:cc:dd:ee:ff"}
    ]
    assert capture.flag == "ESGI{Test_Flag}"


def test_detect_sql_injection_with_legitimate_traffic():
    # Given
    capture = Capture()
    payload = b"GET /index.html?page=accueil HTTP/1.1"
    capture.packets = [
        Ether(src="11:11:11:11:11:11") / IP(src="10.0.0.2") / TCP(dport=80) / Raw(payload)
    ]

    # When
    capture.detect_sql_injection()

    # Then
    assert capture.attacks == []
    assert capture.flag is None

def test_get_json_attacks():
    # Given
    capture = Capture()
    capture.add_attack("arp_spoofing", "ARP", "192.168.1.1", "aa:bb:cc:dd:ee:ff")
    capture.add_attack("port_scan", "TCP", "10.0.0.5", "11:11:11:11:11:11")
    capture.add_attack("sql_injection", "TCP", "10.0.0.9", "11:11:11:11:11:11")

    # When
    result = capture.get_json_attacks()

    # Then
    assert result == [
        {"type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff"},
        {"type": "port_scan", "attacker": "10.0.0.5"},
        {"type": "sql_injection", "attacker": "10.0.0.9"},
    ]
       
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


def test_gen_summary_without_attack():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == "Tout va bien, aucun trafic illegitime detecte."


def test_gen_summary_with_attacks():
    # Given
    capture = Capture()
    capture.add_attack("arp_spoofing", "ARP", "192.168.1.1", "aa:bb:cc:dd:ee:ff")
    capture.flag = "ESGI{Test_Flag}"

    # When
    result = capture._gen_summary()

    # Then
    assert "arp_spoofing" in result
    assert "aa:bb:cc:dd:ee:ff" in result
    assert "ESGI{Test_Flag}" in result