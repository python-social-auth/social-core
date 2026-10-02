from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from social_core.backends.github import GithubOAuth2
from social_core.backends.telegram import TelegramAuth
from social_core.pipeline.social_auth import social_names
from social_core.tests.backends.test_base import get_backend
from social_core.utils import normalize_user_names


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        (("Mary Jane Watson", "", ""), ("Mary Jane Watson", "Mary", "Jane Watson")),
        (("Prince", "", ""), ("Prince", "Prince", "")),
        ((None, None, None), ("", "", "")),
        (("  ", " ", "\t"), ("", "", "")),
        (("  Ada   Lovelace  ", "", ""), ("Ada   Lovelace", "Ada", "Lovelace")),
        (("", " Ada ", " Lovelace "), ("Ada Lovelace", "Ada", "Lovelace")),
        (("", "Prince", ""), ("Prince", "Prince", "")),
        (("", "", "Watson"), ("Watson", "", "Watson")),
        (("", "Jane", "Jane Watson"), ("Jane Watson", "Jane", "Jane Watson")),
        (("", "Jane", "Jane"), ("Jane", "Jane", "Jane")),
        (("", "Ann", "Anniston"), ("Ann Anniston", "Ann", "Anniston")),
        (("", "Ann", "McAnn"), ("Ann McAnn", "Ann", "McAnn")),
        (("", "Ann", "Mary Ann Watson"), ("Mary Ann Watson", "Ann", "Mary Ann Watson")),
        (
            ("", "Mary Jane", "Mary Jane Watson"),
            ("Mary Jane Watson", "Mary Jane", "Mary Jane Watson"),
        ),
        (("", "Jane", "Jane\tWatson"), ("Jane\tWatson", "Jane", "Jane\tWatson")),
        (("", "Jane", "jane Watson"), ("Jane jane Watson", "Jane", "jane Watson")),
        (("Žofie Černá", "", ""), ("Žofie Černá", "Žofie", "Černá")),
        (("Display Name", "Given", "Surname"), ("Display Name", "Given", "Surname")),
        (("Display Name", "Given", ""), ("Display Name", "Given", "")),
        (("Display Name", "", "Surname"), ("Display Name", "", "Surname")),
    ],
)
def test_normalize_user_names(supplied, expected) -> None:
    assert normalize_user_names(*supplied) == expected


def test_get_user_names_deprecated() -> None:
    backend = get_backend({})
    with pytest.warns(
        DeprecationWarning, match=r"BaseAuth.get_user_names\(\)"
    ) as caught:
        names = backend.get_user_names("Mary Jane Watson")
    assert names == ("Mary Jane Watson", "Mary", "Jane Watson")
    assert caught[0].filename == str(Path(__file__))


def test_social_names_preserves_details_and_is_idempotent() -> None:
    backend = get_backend({})
    details = {"fullname": "Mary Jane Watson", "email": "mary@example.com"}
    normalized = social_names(backend, details)["details"]
    assert normalized == {
        "fullname": "Mary Jane Watson",
        "first_name": "Mary",
        "last_name": "Jane Watson",
        "email": "mary@example.com",
    }
    assert details == {"fullname": "Mary Jane Watson", "email": "mary@example.com"}
    assert social_names(backend, normalized)["details"] == normalized


@pytest.mark.parametrize(
    "details", [{}, {"fullname": None, "first_name": None, "last_name": None}]
)
def test_social_names_preserves_absent_names(details) -> None:
    # Apple supplies names only on the first login; None must not clear names.
    assert social_names(get_backend({}), details)["details"] == details


def test_social_names_trims_empty_names() -> None:
    details = {"fullname": "  ", "first_name": "\t", "last_name": None}
    assert social_names(get_backend({}), details)["details"] == {
        "fullname": "",
        "first_name": "",
        "last_name": None,
    }


@pytest.mark.parametrize(
    ("settings", "details", "expected"),
    [
        (
            {"SOCIAL_AUTH_FIRSTLAST_FROM_FULL": False},
            {"fullname": "Ada Lovelace"},
            {"fullname": "Ada Lovelace", "first_name": "", "last_name": ""},
        ),
        (
            {"SOCIAL_AUTH_FULL_FROM_FIRSTLAST": False},
            {"first_name": "Ada", "last_name": "Lovelace"},
            {"fullname": "", "first_name": "Ada", "last_name": "Lovelace"},
        ),
        (
            {
                "SOCIAL_AUTH_FIRSTLAST_FROM_FULL": False,
                "SOCIAL_AUTH_EXAMPLE_FIRSTLAST_FROM_FULL": True,
            },
            {"fullname": "Ada Lovelace"},
            {"fullname": "Ada Lovelace", "first_name": "Ada", "last_name": "Lovelace"},
        ),
        (
            {
                "SOCIAL_AUTH_FULL_FROM_FIRSTLAST": False,
                "SOCIAL_AUTH_EXAMPLE_FULL_FROM_FIRSTLAST": True,
            },
            {"first_name": "Ada"},
            {"fullname": "Ada", "first_name": "Ada", "last_name": ""},
        ),
        (
            {"SOCIAL_AUTH_EXAMPLE_FIRSTLAST_FROM_FULL": False},
            {"fullname": "Ada Lovelace"},
            {"fullname": "Ada Lovelace", "first_name": "", "last_name": ""},
        ),
        (
            {"SOCIAL_AUTH_EXAMPLE_FULL_FROM_FIRSTLAST": False},
            {"last_name": "Lovelace"},
            {"fullname": "", "first_name": "", "last_name": "Lovelace"},
        ),
    ],
)
def test_social_names_switches(settings, details, expected) -> None:
    assert social_names(get_backend(settings), details)["details"] == expected


def test_github_extracts_names_without_conversion() -> None:
    backend = GithubOAuth2(get_backend({}).strategy)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        details = backend.get_user_details({"name": "Mary Jane Watson"})
        assert details["fullname"] == "Mary Jane Watson"
        assert not details["first_name"]
        assert not details["last_name"]
        assert social_names(backend, details)["details"]["last_name"] == "Jane Watson"


def test_telegram_extracts_names_without_conversion() -> None:
    backend = TelegramAuth(get_backend({}).strategy)
    details = backend.get_user_details(
        {"id": 1, "first_name": "Jane", "last_name": "Jane Watson"}
    )
    assert not details["fullname"]
    assert social_names(backend, details)["details"]["fullname"] == "Jane Watson"
