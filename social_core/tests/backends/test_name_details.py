from __future__ import annotations

from unittest.mock import patch

import pytest

from social_core.backends.eveonline import EVEOnlineOAuth2
from social_core.pipeline.social_auth import social_names
from social_core.tests.backends.test_base import get_backend
from social_core.utils import module_member


@pytest.mark.parametrize(
    ("backend_path", "response", "raw_names", "normalized_names"),
    [
        (
            f"social_core.backends.{backend_path}",
            response,
            (" Mary Jane Watson ", "", ""),
            ("Mary Jane Watson", "Mary", "Jane Watson"),
        )
        for backend_path, response in [
            ("coding.CodingOAuth2", {"name": " Mary Jane Watson "}),
            ("docker.DockerOAuth2", {"full_name": " Mary Jane Watson "}),
            ("douban.DoubanOAuth2", {"name": " Mary Jane Watson "}),
            ("einfracz.EInfraCZOpenIdConnect", {"name": " Mary Jane Watson "}),
            ("elixir.ElixirOpenIdConnect", {"name": " Mary Jane Watson "}),
            ("globus.GlobusOpenIdConnect", {"name": " Mary Jane Watson "}),
            ("meetup.MeetupOAuth2", {"name": " Mary Jane Watson "}),
            (
                "monzo.MonzoOAuth2",
                {"accounts": [{"description": " Mary Jane Watson "}]},
            ),
            ("trello.TrelloOAuth", {"fullName": " Mary Jane Watson "}),
            ("uffd.UffdOAuth2", {"name": " Mary Jane Watson "}),
            ("vimeo.VimeoOAuth1", {"person": {"display_name": " Mary Jane Watson "}}),
            ("vimeo.VimeoOAuth2", {"user": {"name": " Mary Jane Watson "}}),
            ("yandex.YandexOAuth2", {"real_name": " Mary Jane Watson "}),
            ("yandex.YaruOAuth2", {"display_name": " Mary Jane Watson "}),
        ]
    ]
    + [
        (
            f"social_core.backends.{backend_path}",
            response,
            ("", " Mary ", " Jane Watson "),
            ("Mary Jane Watson", "Mary", "Jane Watson"),
        )
        for backend_path, response in [
            (
                "classlink.ClasslinkOAuth",
                {"FirstName": " Mary ", "LastName": " Jane Watson "},
            ),
            (
                "justgiving.JustGivingOAuth2",
                {"firstName": " Mary ", "lastName": " Jane Watson "},
            ),
            (
                "ping.PingOpenIdConnect",
                {"given_name": " Mary ", "family_name": " Jane Watson "},
            ),
        ]
    ]
    + [
        (
            "social_core.backends.egi_checkin.EGICheckinOpenIdConnect",
            {
                "name": " Display Name ",
                "given_name": " Mary ",
                "family_name": " Jane Watson ",
            },
            (" Display Name ", " Mary ", " Jane Watson "),
            ("Display Name", "Mary", "Jane Watson"),
        ),
        (
            "social_core.backends.odnoklassniki.OdnoklassnikiOAuth2",
            {
                "uid": "123",
                "name": "Mary%20Watson",
                "first_name": "Mary",
                "last_name": "Watson",
            },
            ("Mary Watson", "Mary", "Watson"),
            ("Mary Watson", "Mary", "Watson"),
        ),
        (
            "social_core.backends.qq.QQOAuth2",
            {"nickname": " Mary Jane Watson "},
            ("", " Mary Jane Watson ", ""),
            ("Mary Jane Watson", "Mary Jane Watson", ""),
        ),
        (
            "social_core.backends.weibo.WeiboOAuth2",
            {"screen_name": " Mary Jane Watson "},
            ("", " Mary Jane Watson ", ""),
            ("Mary Jane Watson", "Mary Jane Watson", ""),
        ),
    ],
)
def test_provider_names_are_normalized_only_in_pipeline(
    backend_path, response, raw_names, normalized_names
) -> None:
    backend = module_member(backend_path)(get_backend({}).strategy)
    details = backend.get_user_details(response)
    keys = ("fullname", "first_name", "last_name")
    assert tuple(details[key] for key in keys) == raw_names
    normalized = social_names(backend, details)["details"]
    assert tuple(normalized[key] for key in keys) == normalized_names
    assert {key: value for key, value in normalized.items() if key not in keys} == {
        key: value for key, value in details.items() if key not in keys
    }


def test_eve_character_name_is_normalized_in_pipeline() -> None:
    backend = EVEOnlineOAuth2(get_backend({}).strategy)
    with patch.object(
        backend, "get_json", return_value={"CharacterName": " Mary Jane Watson "}
    ):
        details = backend.get_user_details({"access_token": "token"})
    assert details["username"] == "Mary Jane Watson"
    assert details["fullname"] == " Mary Jane Watson "
    assert details["first_name"] == details["last_name"] == ""
    normalized = social_names(backend, details)["details"]
    assert normalized["first_name"] == "Mary"
    assert normalized["last_name"] == "Jane Watson"
