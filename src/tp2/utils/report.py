from fpdf import FPDF


def clean_text(value: object) -> str:
    """
    Les polices de base du PDF ne gerent que le latin-1 : on remplace les autres caracteres
    """
    return str(value).encode("latin-1", "replace").decode("latin-1")


def generate_report(result: dict, path: str) -> None:
    """
    Genere un rapport PDF lisible a partir du resultat du triage
    """
    pdf = FPDF()
    pdf.add_page()
    width = pdf.epw  # largeur utile de la page

    # Titre et verdict, ce que l'analyste doit voir en premier
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "B", 12)
    verdict = f"Famille : {result['family_guess']}  -  Score : {result['score']}/10"
    pdf.cell(0, 10, clean_text(verdict), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(3)

    def section(title: str) -> None:
        """
        Ajoute un titre de section au rapport
        """
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)

    def line(label: str, value: object) -> None:
        """
        Ajoute une ligne "label : valeur" au rapport
        """
        pdf.multi_cell(width, 6, clean_text(f"{label} : {value}"), new_x="LMARGIN", new_y="NEXT")

    section("Fichier")
    line("SHA-256", result["sha256"])
    line("MD5", result["md5"])
    line("Taille", f"{result['size']} octets")
    line("Type", result["file_type"])
    line("Entropie", result["entropy"])

    section("Indicateurs de compromission")
    for key, values in result["iocs"].items():
        line(key, ", ".join(values) if values else "aucun")

    section("Detection")
    line("Fonctions suspectes", ", ".join(result["imports"]) or "aucune")
    line("Regles YARA", ", ".join(result["yara_matches"]) or "aucune")
    line("MITRE ATT&CK", ", ".join(result["mitre_attack"]) or "aucune")
    line("Flag", result["flag"] or "non trouve")

    section("Resume")
    pdf.multi_cell(width, 6, clean_text(result["llm_summary"]), new_x="LMARGIN", new_y="NEXT")

    pdf.output(path)
