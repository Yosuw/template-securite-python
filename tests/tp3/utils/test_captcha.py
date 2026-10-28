import io

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from src.tp3.utils.captcha import (
    BOX,
    CHARSET,
    FONT_PATH,
    Captcha,
    _normalize,
    build_templates,
    segment,
)

TEMPLATES = build_templates()


def render_captcha(text: str) -> bytes:
    """Fabrique une image de captcha comme le serveur, pour les tests."""
    font = ImageFont.truetype(str(FONT_PATH), 48)
    img = Image.new("L", (260, 90), 255)
    draw = ImageDraw.Draw(img)
    x = 20
    for char in text:
        draw.text((x, 28), char, fill=0, font=font)
        x += draw.textbbox((x, 28), char, font=font)[2] - x + 12
    buffer = io.BytesIO()
    img.save(buffer, "PNG")
    return buffer.getvalue()


def test_build_templates():
    templates = build_templates()
    assert len(templates) == len(CHARSET)
    assert templates["A"].shape == (BOX[1], BOX[0])


def test_segment_counts_glyphs():
    # Trois blocs noirs separes par des colonnes blanches
    mask = np.zeros((10, 30), dtype=bool)
    mask[:, 0:5] = True
    mask[:, 12:17] = True
    mask[:, 24:29] = True
    assert len(segment(mask)) == 3


def test_solve():
    captcha = Captcha(render_captcha("AB7K9"), TEMPLATES)
    assert captcha.solve() == "AB7K9"


def test_get_value():
    captcha = Captcha(render_captcha("XYZ12"), TEMPLATES)
    captcha.solve()
    assert captcha.get_value() == "XYZ12"


def test_normalize_shape_and_content():
    # un petit bloc noir decentre -> recadre et redimensionne a la taille fixe
    mask = np.zeros((20, 20), dtype=bool)
    mask[4:9, 6:10] = True
    result = _normalize(mask)
    assert result.shape == (BOX[1], BOX[0])
    assert result.any()
