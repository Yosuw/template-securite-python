import hashlib
import math

import magic


def shannon_entropy(data: bytes) -> float:
    """
    Calcule l'entropie de Shannon des donnees (entre 0 et 8)
    """
    if not data:
        return 0.0
    # Nombre d'apparitions de chaque octet
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def get_file_metadata(data: bytes) -> dict:
    """
    Retourne les empreintes, la taille, le type et l'entropie du fichier
    """
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "entropy": shannon_entropy(data),
        # python-magic devine le type du fichier a partir de son contenu
        "file_type": magic.from_buffer(data),
    }
