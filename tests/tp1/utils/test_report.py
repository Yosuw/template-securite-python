from unittest.mock import MagicMock, patch

from fpdf import FPDF

from src.tp1.utils.report import Report


def test_report_init():
    # Given
    capture = MagicMock()
    filename = "test.pdf"
    summary = "Test summary"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "Rapport TP1 - Analyse du trafic reseau"
    assert report.summary == summary
    assert report.array == []
    assert report.graph == ""


def test_concat_report():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    result = report.concat_report()

    # Then
    assert isinstance(result, FPDF)
    assert result.page_no() == 1


def test_concat_report_with_array():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.array = [("TCP", 5), ("ARP", 1)]

    # When
    result = report.concat_report()

    # Then
    assert isinstance(result, FPDF)


def test_concat_report_with_graph(tmp_path):
    # Given
    # On genere une vraie image PNG dans un dossier temporaire
    import pygal

    graph_path = str(tmp_path / "graph.png")
    chart = pygal.Bar()
    chart.add("Paquets", [5, 1])
    chart.render_to_png(graph_path)

    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.graph = graph_path

    # When
    result = report.concat_report()

    # Then
    assert isinstance(result, FPDF)


def test_save(tmp_path):
    # Given
    # tmp_path est un dossier temporaire fourni par pytest
    filename = str(tmp_path / "test.pdf")
    report = Report(MagicMock(), filename, "Test summary")

    # When
    report.save(filename)

    # Then
    # Un vrai fichier PDF commence toujours par %PDF
    with open(filename, "rb") as f:
        assert f.read(4) == b"%PDF"


def test_generate_graph():
    # Given
    capture = MagicMock()
    capture.sort_network_protocols.return_value = {"TCP": 5, "ARP": 1}
    report = Report(capture, "test.pdf", "Test summary")

    # When
    # On simule pygal pour ne pas creer de fichier pendant le test
    with patch("src.tp1.utils.report.pygal") as mock_pygal:
        report.generate("graph")

    # Then
    mock_pygal.Bar().add.assert_called_once_with("Paquets", [5, 1])
    mock_pygal.Bar().render_to_png.assert_called_once_with("graph.png")
    assert report.graph == "graph.png"


def test_generate_array():
    # Given
    capture = MagicMock()
    capture.sort_network_protocols.return_value = {"TCP": 5, "ARP": 1}
    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array == [("TCP", 5), ("ARP", 1)]


def test_generate_invalid_param():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == ""
    assert report.array == []
