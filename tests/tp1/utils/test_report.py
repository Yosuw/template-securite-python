from unittest.mock import MagicMock
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
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    report.generate("graph")

    # Then
    assert report.graph == ""  # Currently returns empty string


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