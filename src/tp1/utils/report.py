import pygal
from fpdf import FPDF

from tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str) -> None:
        self.capture = capture
        self.filename = filename
        self.title = "Rapport TP1 - Analyse du trafic reseau"
        self.summary = summary
        # lignes du tableau : (protocole, nombre de paquets)
        self.array: list[tuple[str, int]] = []
        self.graph = ""  # chemin de l'image du graphique

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
        pdf.ln(5)

        # Tableau des protocoles s'il a ete genere
        if self.array:
            # En-tete du tableau
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(90, 8, "Protocole", border=1)
            pdf.cell(90, 8, "Nombre de paquets", border=1, new_x="LMARGIN", new_y="NEXT")

            # Une ligne par protocole
            pdf.set_font("Helvetica", size=11)
            for protocol, count in self.array:
                pdf.cell(90, 8, protocol, border=1)
                pdf.cell(90, 8, str(count), border=1, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)

        # Ajout du graphique s'il a ete genere
        if self.graph:
            pdf.image(self.graph, w=180)

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
            # Protocoles tries par nombre de paquets
            protocols = self.capture.sort_network_protocols()
            # Diagramme en barres : une barre par protocole
            chart = pygal.Bar()
            chart.title = "Nombre de paquets par protocole"
            chart.x_labels = list(protocols.keys())
            chart.add("Paquets", list(protocols.values()))
            # Export en PNG pour pouvoir l'inserer dans le PDF
            graph = "graph.png"
            chart.render_to_png(graph)
            self.graph = graph
        elif param == "array":
            # Protocoles tries par nombre de paquets
            protocols = self.capture.sort_network_protocols()
            # Construction des lignes du tableau
            array = []
            for protocol in protocols:
                array.append((protocol, protocols[protocol]))
            self.array = array
