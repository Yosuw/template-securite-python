class Captcha:
    def __init__(self, url):
        """
        Initialise le captcha a resoudre a partir de son URL
        """
        self.url = url
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = "FIXME"

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
