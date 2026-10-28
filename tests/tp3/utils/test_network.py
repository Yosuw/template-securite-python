import base64
import socket
import threading

from src.tp3.utils.network import Network, xor


def test_xor():
    # XOR est reversible : (a ^ k) ^ k == a
    assert xor(b"hello", b"K") == bytes(c ^ ord("K") for c in b"hello")
    assert xor(xor(b"data", b"\x01\x02"), b"\x01\x02") == b"data"


def test_process_line_token():
    net = Network("h", 1, "ff193b22")
    # vecteur releve a la main sur la cible : base64 -> XOR cle hex -> jeton clair
    action = net.process_line(b"xysCFJkuXxGbfFpEnSFYEw==")
    assert action == ("token", b"8296f7d3deafb8c1")


def test_process_line_flag():
    net = Network("h", 1, "ff193b22")
    assert net.process_line(b"OK ESGI{chain_test}") == ("flag", "ESGI{chain_test}")


def test_process_line_ignored():
    net = Network("h", 1, "ff193b22")
    # ligne d'instructions : pas du base64 -> ignoree
    assert net.process_line(b"Decode each line: base64 then XOR") is None
    assert net.process_line(b"") is None


def _fake_server(sock, key):
    """Petit serveur de test qui envoie 2 jetons puis le flag."""
    conn, _ = sock.accept()
    stream = conn.makefile("rwb")
    stream.write(b"Decode each line: base64 then XOR\n")
    stream.flush()
    for clear in (b"token_round_1aa", b"token_round_2bb"):
        encoded = base64.b64encode(xor(clear, bytes.fromhex(key)))
        stream.write(encoded + b"\n")
        stream.flush()
        reply = stream.readline().strip()
        if reply != clear:  # mauvaise reponse -> on coupe
            conn.close()
            return
    stream.write(b"OK ESGI{chain_test_flag}\n")
    stream.flush()
    conn.close()


def test_run_full_exchange():
    # Given : un serveur local qui joue le protocole
    key = "ff193b22"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    thread = threading.Thread(target=_fake_server, args=(server, key), daemon=True)
    thread.start()

    # When
    flag = Network("127.0.0.1", port, key, timeout=10).run()

    # Then
    assert flag == "ESGI{chain_test_flag}"
    server.close()
