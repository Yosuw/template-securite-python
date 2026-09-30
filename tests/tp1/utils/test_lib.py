from unittest.mock import patch

from src.tp1.utils.lib import choose_interface, hello_world


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_when_choose_interface_then_return_chosen_interface():
    # Given
    with (
        patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"]),
        patch("builtins.input", return_value="1"),
    ):
        # When
        result = choose_interface()

    # Then
    assert result == "eth0"


def test_when_choose_interface_with_invalid_choice_then_ask_again():
    # Given
    with (
        patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"]),
        patch("builtins.input", side_effect=["9", "abc", "0"]),
    ):
        # When
        result = choose_interface()

    # Then
    assert result == "lo"
