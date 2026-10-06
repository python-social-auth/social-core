from __future__ import annotations

import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

from social_core.backends.github import GithubOAuth2
from social_core.backends.telegram import TelegramAuth
from social_core.pipeline.social_auth import social_names
from social_core.pipeline.user import user_details
from social_core.tests.backends.test_base import get_backend
from social_core.tests.models import UserWithNames
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
            {"fullname": "Ada Lovelace"},
        ),
        (
            {"SOCIAL_AUTH_FULL_FROM_FIRSTLAST": False},
            {"first_name": "Ada", "last_name": "Lovelace"},
            {"first_name": "Ada", "last_name": "Lovelace"},
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
            {"fullname": "Ada", "first_name": "Ada"},
        ),
        (
            {"SOCIAL_AUTH_EXAMPLE_FIRSTLAST_FROM_FULL": False},
            {"fullname": "Ada Lovelace"},
            {"fullname": "Ada Lovelace"},
        ),
        (
            {"SOCIAL_AUTH_EXAMPLE_FULL_FROM_FIRSTLAST": False},
            {"last_name": "Lovelace"},
            {"last_name": "Lovelace"},
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


@pytest.mark.parametrize(
    ("details", "expected"),
    [
        ({"first_name": "Ada"}, {"fullname": "Ada", "first_name": "Ada"}),
        (
            {"first_name": "Ada", "last_name": None},
            {"fullname": "Ada", "first_name": "Ada", "last_name": None},
        ),
        (
            {"first_name": "Ada", "last_name": ""},
            {"fullname": "Ada", "first_name": "Ada", "last_name": ""},
        ),
        ({"fullname": "Prince"}, {"fullname": "Prince", "first_name": "Prince"}),
        (
            {"fullname": "Prince", "first_name": None, "last_name": None},
            {"fullname": "Prince", "first_name": "Prince", "last_name": None},
        ),
        (
            {"fullname": "Ada Lovelace", "first_name": "", "last_name": ""},
            {"fullname": "Ada Lovelace", "first_name": "Ada", "last_name": "Lovelace"},
        ),
        (
            {"fullname": "", "first_name": "Ada", "last_name": "Lovelace"},
            {"fullname": "Ada Lovelace", "first_name": "Ada", "last_name": "Lovelace"},
        ),
        (
            {"fullname": "Display Name", "first_name": "Given", "last_name": None},
            {"fullname": "Display Name", "first_name": "Given", "last_name": None},
        ),
    ],
)
def test_social_names_preserves_unavailable_components(details, expected) -> None:
    backend = get_backend({})
    normalized = social_names(backend, details)["details"]
    assert normalized == expected
    assert social_names(backend, normalized)["details"] == expected


@pytest.mark.parametrize(
    ("details", "settings", "expected"),
    [
        ({}, {}, ("Existing Full Name", "Existing", "Surname")),
        (
            {"fullname": None, "first_name": None, "last_name": None},
            {},
            ("Existing Full Name", "Existing", "Surname"),
        ),
        ({"first_name": "Ada"}, {}, ("Ada", "Ada", "Surname")),
        ({"fullname": "Prince"}, {}, ("Prince", "Prince", "Surname")),
        ({"first_name": "Ada", "last_name": ""}, {}, ("Ada", "Ada", "")),
        ({"fullname": "", "first_name": "", "last_name": ""}, {}, ("", "", "")),
        (
            {"fullname": "Ada Lovelace"},
            {"SOCIAL_AUTH_FIRSTLAST_FROM_FULL": False},
            ("Ada Lovelace", "Existing", "Surname"),
        ),
        (
            {"first_name": "Ada", "last_name": "Lovelace"},
            {"SOCIAL_AUTH_FULL_FROM_FIRSTLAST": False},
            ("Existing Full Name", "Ada", "Lovelace"),
        ),
        (
            {"first_name": "Ada"},
            {"SOCIAL_AUTH_PROTECTED_USER_FIELDS": ["first_name", "fullname"]},
            ("Existing Full Name", "Existing", "Surname"),
        ),
        (
            {"first_name": "Ada"},
            {"SOCIAL_AUTH_IMMUTABLE_USER_FIELDS": ["first_name", "fullname"]},
            ("Existing Full Name", "Existing", "Surname"),
        ),
    ],
)
def test_name_normalization_updates_only_available_fields(
    details, settings, expected
) -> None:
    backend = get_backend(settings)
    user = UserWithNames(username="existing", email="existing@example.com")
    user.fullname, user.first_name, user.last_name = (
        "Existing Full Name",
        "Existing",
        "Surname",
    )
    normalized = social_names(backend, details)["details"]
    with patch.object(backend.strategy.storage.user, "changed") as changed:
        user_details(backend.strategy, normalized, backend, user)
    assert (user.fullname, user.first_name, user.last_name) == expected
    assert user.email == "existing@example.com"
    assert user.username == "existing"
    assert changed.call_count == (
        expected != ("Existing Full Name", "Existing", "Surname")
    )
