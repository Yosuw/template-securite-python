from unittest.mock import MagicMock, patch

import requests

from src.tp2.utils.llm import LLMClient, build_prompt, parse_llm_response


def test_build_prompt_uses_delimiters():
    prompt = build_prompt({"ips": ["10.0.0.5"]})
    assert prompt.startswith("<DONNEES_NON_FIABLES>")
    assert prompt.endswith("</DONNEES_NON_FIABLES>")
    assert "10.0.0.5" in prompt


def test_parse_llm_response_valid():
    text = (
        'Voici : {"famille": "dropper", "capacites": ["telechargement"], '
        '"mitre_attack": ["T1105", "faux"], "score_0_10": 8, "resume": "ok"}'
    )
    result = parse_llm_response(text)
    assert result == {
        "family": "dropper",
        "capabilities": ["telechargement"],
        "mitre_attack": ["T1105"],
        "score": 8,
        "summary": "ok",
    }


def test_parse_llm_response_score_is_bounded():
    text = '{"famille": "x", "capacites": [], "mitre_attack": [], "score_0_10": 42}'
    assert parse_llm_response(text)["score"] == 10


def test_parse_llm_response_invalid():
    assert parse_llm_response(None) is None
    assert parse_llm_response("pas de json") is None
    # Champ manquant
    assert parse_llm_response('{"famille": "x"}') is None


def test_llm_client_default_backend(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert LLMClient().backend == "ollama"
    monkeypatch.setenv("OPENROUTER_API_KEY", "cle")
    assert LLMClient().backend == "openrouter"


def test_llm_client_ollama():
    response = MagicMock()
    response.json.return_value = {"message": {"content": "reponse"}}
    with patch("src.tp2.utils.llm.requests.post", return_value=response):
        assert LLMClient("ollama").ask("system", "user") == "reponse"


def test_llm_client_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "cle")
    response = MagicMock()
    response.json.return_value = {"choices": [{"message": {"content": "reponse"}}]}
    with patch("src.tp2.utils.llm.requests.post", return_value=response):
        assert LLMClient("openrouter").ask("system", "user") == "reponse"


def test_llm_client_without_network():
    # Sans reseau, le client retourne None au lieu de planter
    with patch("src.tp2.utils.llm.requests.post", side_effect=requests.ConnectionError("pas de reseau")):
        assert LLMClient("ollama").ask("system", "user") is None


def test_ask_ollama():
    # Given
    response = MagicMock()
    response.json.return_value = {"message": {"content": "ok"}}

    # When
    with patch("src.tp2.utils.llm.requests.post", return_value=response) as mock_post:
        result = LLMClient("ollama")._ask_ollama("system", "user")

    # Then : la requete part bien vers le serveur Ollama local
    assert result == "ok"
    assert mock_post.call_args.args[0] == "http://localhost:11434/api/chat"
    assert mock_post.call_args.kwargs["json"]["stream"] is False


def test_ask_openrouter(monkeypatch):
    # Given
    monkeypatch.setenv("OPENROUTER_API_KEY", "cle-test")
    response = MagicMock()
    response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}

    # When
    with patch("src.tp2.utils.llm.requests.post", return_value=response) as mock_post:
        result = LLMClient("openrouter")._ask_openrouter("system", "user")

    # Then : la cle API est envoyee dans l'en-tete
    assert result == "ok"
    assert mock_post.call_args.args[0] == "https://openrouter.ai/api/v1/chat/completions"
    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer cle-test"
