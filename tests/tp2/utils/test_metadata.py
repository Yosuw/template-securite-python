import hashlib

from src.tp2.utils.metadata import get_file_metadata, shannon_entropy


def test_shannon_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_same_bytes():
    # Un seul octet repete : aucune incertitude
    assert shannon_entropy(b"AAAAAAAA") == 0.0


def test_shannon_entropy_all_bytes():
    # Les 256 valeurs une fois chacune : entropie maximale
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_get_file_metadata():
    # Given
    data = b"hello world"

    # When
    result = get_file_metadata(data)

    # Then
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["md5"] == hashlib.md5(data).hexdigest()
    assert result["size"] == 11
    assert result["file_type"].startswith("ASCII text")
    assert 0 < result["entropy"] < 8
