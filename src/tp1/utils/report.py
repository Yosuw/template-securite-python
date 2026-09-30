from fpdf import FPDF

from tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport TP1 - Analyse du trafic reseau"
        self.summary = summary
        self.array = []   # lignes du tableau : (protocole, nombre de paquets)
        self.graph = ""   # chemin de l'image du graphique

    def concat_report(self) -> FPDF:
        """
        Concat all data in report
        """
        pdf = FPDF()
        pdf.add_page()

        # Titre du rapport
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)

        # Resume de l'analyse (attaques detectees ou "tout va bien")
        pdf.set_font("Helvetica", size=11)
        pdf.multi_cell(0, 7, self.summary)

        return pdf

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        final_content = self.concat_report()
        # Ecriture du fichier PDF
        final_content.output(self.filename)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            # TODO: generate graph
            graph = ""
            self.graph = graph
        elif param == "array":
            # TODO: generate array
            array = []
            self.array = array