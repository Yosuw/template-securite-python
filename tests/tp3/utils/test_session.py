import io
from unittest.mock import MagicMock

from PIL import Image, ImageDraw, ImageFont

from src.tp3.utils.captcha import FONT_PATH
from src.tp3.utils.session import Session


def render_captcha(text: str) -> bytes:
    """Image de captcha pour les tests, meme police que le serveur."""
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


def fake_response(status=200, text="", content=b"", json_data=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.content = content
    if json_data is None:
        resp.json.side_effect = ValueError("pas de json")
    else:
        resp.json.return_value = json_data
    return resp


def make_session(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("accueil\ninternal-panel\nautre\n")
    return Session("http://cible", wordlist=wl)


def test_words(tmp_path):
    session = make_session(tmp_path)
    assert session.words() == ["accueil", "internal-panel", "autre"]


def test_find_endpoint(tmp_path):
    session = make_session(tmp_path)
    # 404 partout sauf sur la page qui contient un formulaire captcha
    session.http = MagicMock()
    session.http.get.side_effect = [
        fake_response(404),
        fake_response(200, text='<form><img src="/captcha.png"><input name="captcha"></form>'),
    ]
    assert session.find_endpoint() == "http://cible/internal-panel"
    assert session.endpoint == "http://cible/internal-panel"


def test_solve_captcha(tmp_path):
    session = make_session(tmp_path)
    session.http = MagicMock()
    session.http.get.return_value = fake_response(content=render_captcha("AB7K9"))
    assert session.solve_captcha() == "AB7K9"


def test_breach(tmp_path):
    session = make_session(tmp_path)
    session.endpoint = "http://cible/internal-panel"
    session.http = MagicMock()
    session.http.get.return_value = fake_response(content=render_captcha("AB7K9"))
    pivot = {"flag1": "ESGI{web}", "host": "127.0.0.1", "port": 9090, "key": "ff193b22"}
    session.http.post.return_value = fake_response(json_data=pivot)

    assert session.breach() == pivot
    assert session.result["flag1"] == "ESGI{web}"
