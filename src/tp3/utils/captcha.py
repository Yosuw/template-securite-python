import io
from pathlib import Path

import matplotlib
import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

# Les captchas utilisent la police DejaVu Sans Bold, livree dans le paquet matplotlib
FONT_PATH = Path(matplotlib.__file__).parent / "mpl-data" / "fonts" / "ttf" / "DejaVuSans-Bold.ttf"
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
BOX = (24, 32)  # taille normalisee d'un glyphe pour la comparaison


def _normalize(mask: np.ndarray) -> np.ndarray:
    """
    Recadre un masque sur sa partie noire et le redimensionne a une taille fixe
    """
    ys = np.where(mask.any(axis=1))[0]
    xs = np.where(mask.any(axis=0))[0]
    crop = mask[ys[0] : ys[-1] + 1, xs[0] : xs[-1] + 1]
    return np.array(Image.fromarray(crop).resize(BOX)) > 0.5


def build_templates(size: int = 56) -> dict:
    """
    Construit un gabarit normalise pour chaque caractere, dans la police de reference
    """
    font = ImageFont.truetype(str(FONT_PATH), size)
    templates = {}
    for char in CHARSET:
        img = Image.new("L", (90, 100), 0)
        ImageDraw.Draw(img).text((5, 5), char, fill=255, font=font)
        templates[char] = _normalize(np.array(img) > 128)
    return templates


def segment(mask: np.ndarray) -> list:
    """
    Decoupe l'image en glyphes grace aux colonnes blanches qui les separent
    """
    columns = mask.sum(axis=0) > 1  # une colonne "pleine" contient plusieurs pixels noirs
    glyphs = []
    start = None
    for x, filled in enumerate(columns):
        if filled and start is None:
            start = x
        elif not filled and start is not None:
            if x - start >= 4:  # on ignore les colonnes de bruit trop fines
                glyphs.append(mask[:, start:x])
            start = None
    if start is not None:
        glyphs.append(mask[:, start:])
    return glyphs


class Captcha:
    """
    Resout un captcha image : texte noir sur fond blanc, police fixe
    """

    def __init__(self, image_bytes: bytes = b"", templates: dict | None = None) -> None:
        """
        Prepare le captcha a partir des octets de l'image
        """
        self.image_bytes = image_bytes
        self.templates = templates if templates is not None else build_templates()
        self.value = ""

    def solve(self) -> str:
        """
        Nettoie l'image, decoupe les glyphes et reconnait chaque caractere
        """
        image = Image.open(io.BytesIO(self.image_bytes)).convert("L")
        image = image.filter(ImageFilter.MedianFilter(3))  # enleve la poussiere
        mask = np.array(image) < 128
        value = ""
        for glyph in segment(mask):
            normalized = _normalize(glyph)
            scores = {c: (normalized == t).sum() for c, t in self.templates.items()}
            value += max(scores, key=scores.get)
        self.value = value
        return value

    def get_value(self) -> str:
        """
        Retourne la valeur reconnue du captcha
        """
        return self.value
