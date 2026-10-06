from __future__ import annotations

from unittest.mock import patch

import pytest

from social_core.backends.eveonline import EVEOnlineOAuth2
from social_core.pipeline.social_auth import social_names
from social_core.pipeline.user import user_details
from social_core.tests.backends.test_base import get_backend
from social_core.tests.models import UserWithNames
from social_core.utils import module_member


@pytest.mark.parametrize(
    ("backend_path", "response", "raw_names", "normalized_names"),
    [
        (
            f"social_core.backends.{backend_path}",
            response,
            (" Mary Jane Watson ", None, None),
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
            (None, " Mary ", " Jane Watson "),
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
            (None, " Mary Jane Watson ", None),
            ("Mary Jane Watson", "Mary Jane Watson", None),
        ),
        (
            "social_core.backends.weibo.WeiboOAuth2",
            {"screen_name": " Mary Jane Watson "},
            (None, " Mary Jane Watson ", None),
            ("Mary Jane Watson", "Mary Jane Watson", None),
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
    assert details["first_name"] is details["last_name"] is None
    normalized = social_names(backend, details)["details"]
    assert normalized["first_name"] == "Mary"
    assert normalized["last_name"] == "Jane Watson"


@pytest.mark.parametrize(
    ("backend_path", "response"),
    [
        ("amazon.AmazonOAuth2", {}),
        ("apple.AppleIdAuth", {"sub": "123"}),
        ("azuread.AzureADOAuth2", {}),
        ("azuread_b2c.AzureADB2COAuth2", {}),
        ("azuread_tenant.AzureADV2TenantOAuth2", {}),
        ("box.BoxOAuth2", {}),
        ("cesid.CesidOpenIdConnect", {}),
        ("chatwork.ChatworkOAuth2", {}),
        ("cilogon.CILogonOAuth2", {}),
        ("classlink.ClasslinkOAuth", {}),
        (
            "clever.CleverOAuth2",
            {"data": {"email": "u@example.com", "roles": {"student": {}}}},
        ),
        ("coding.CodingOAuth2", {}),
        ("cognito.CognitoOAuth2", {}),
        ("deezer.DeezerOAuth2", {}),
        ("digitalocean.DigitalOceanOAuth", {"account": {"email": "u@example.com"}}),
        ("docker.DockerOAuth2", {}),
        ("douban.DoubanOAuth2", {}),
        ("dribbble.DribbbleOAuth2", {}),
        ("egi_checkin.EGICheckinOpenIdConnect", {}),
        ("einfracz.EInfraCZOpenIdConnect", {}),
        ("elixir.ElixirOpenIdConnect", {}),
        ("facebook.FacebookOAuth2", {}),
        ("flickr.FlickrOAuth", {}),
        (
            "foursquare.FoursquareOAuth2",
            {"response": {"user": {"contact": {"email": "u@example.com"}}}},
        ),
        ("gitea.GiteaOAuth2", {}),
        ("github.GithubOAuth2", {}),
        ("gitlab.GitLabOAuth2", {}),
        ("globus.GlobusOpenIdConnect", {}),
        ("goclio.GoClioOAuth2", {"user": {}}),
        ("google.GoogleOAuth2", {}),
        ("helmholtz.HelmholtzOpenIdConnect", {}),
        ("instagram.InstagramOAuth2", {"user": {"username": "u"}}),
        ("justgiving.JustGivingOAuth2", {}),
        ("kakao.KakaoOAuth2", {}),
        ("kick.KickOAuth2", {}),
        ("legacy.LegacyAuth", {}),
        ("lifescience.LifeScienceOpenIdConnect", {}),
        ("lifescience_eosc.LifeScienceEoscOpenIdConnect", {}),
        ("line.LineOAuth2", {}),
        (
            "linkedin.LinkedinOAuth2",
            {
                "firstName": {
                    "preferredLocale": {"language": "en", "country": "US"},
                    "localized": {},
                },
                "lastName": {
                    "preferredLocale": {"language": "en", "country": "US"},
                    "localized": {},
                },
            },
        ),
        ("live.LiveOAuth2", {}),
        (
            "mapmyfitness.MapMyFitnessOAuth2",
            {"username": "u", "email": "u@example.com"},
        ),
        ("meetup.MeetupOAuth2", {}),
        ("microsoft.MicrosoftOAuth2", {"userPrincipalName": "u@example.com"}),
        ("nationbuilder.NationBuilderOAuth2", {}),
        ("nfdi.NFDIOpenIdConnect", {}),
        ("openstreetmap_oauth2.OpenStreetMapOAuth2", {"username": "u"}),
        ("orbi.OrbiOAuth2", {}),
        ("orcid.ORCIDOAuth2", {"orcid-identifier": {"path": "123"}}),
        (
            "orcid.ORCIDOAuth2",
            {"person": {"name": {"given-names": None, "family-name": None}}},
        ),
        ("paypal.PayPalOAuth2", {"user_id": "https://example.com/123"}),
        ("phabricator.PhabricatorOAuth2", {}),
        ("ping.PingOpenIdConnect", {}),
        ("pixelpin.PixelPinOpenIDConnect", {"sub": "123"}),
        ("qq.QQOAuth2", {}),
        ("reddit.RedditOAuth2", {}),
        ("simplelogin.SimpleLoginOAuth2", {}),
        ("sketchfab.SketchfabOAuth2", {"username": "u"}),
        ("soundcloud.SoundcloudOAuth2", {}),
        ("spotify.SpotifyOAuth2", {}),
        ("stackoverflow.StackoverflowOAuth2", {"link": "https://example.com/u"}),
        ("strava.StravaOAuth", {"athlete": {}}),
        ("stripe.StripeOAuth2", {}),
        ("telegram.TelegramAuth", {"id": "123"}),
        ("trello.TrelloOAuth", {}),
        ("twitch.TwitchOAuth2", {}),
        ("uber.UberOAuth2", {}),
        ("uffd.UffdOAuth2", {}),
        ("untappd.UntappdOAuth2", {"user": {}}),
        ("upwork.UpworkOAuth", {}),
        ("vend.VendOAuth2", {"email": "u@example.com"}),
        ("vimeo.VimeoOAuth1", {}),
        ("vimeo.VimeoOAuth2", {}),
        ("vk.VKontakteOpenAPI", {"id": "123"}),
        ("vk.VKOAuth2", {}),
        ("vk.VKIDOAuth2", {}),
        ("weibo.WeiboOAuth2", {}),
        ("wlcg.WLCGOAuth2", {}),
        ("yahoo.YahooOAuth2", {}),
        ("yandex.YandexOAuth2", {}),
        ("yandex.YaruOAuth2", {}),
        ("zoom.ZoomOAuth2", {}),
    ],
)
def test_unavailable_provider_names_preserve_existing_profile(
    backend_path, response
) -> None:
    backend = module_member(f"social_core.backends.{backend_path}")(
        get_backend({}).strategy
    )
    details = backend.get_user_details(response)
    keys = ("fullname", "first_name", "last_name")
    assert all(details.get(key) is None for key in keys)
    normalized = social_names(backend, details)["details"]
    user = UserWithNames(username="existing", email="existing@example.com")
    user.fullname, user.first_name, user.last_name = "Existing Name", "Existing", "Name"
    with patch.object(backend.strategy.storage.user, "changed") as changed:
        user_details(backend.strategy, normalized, backend, user)
    assert (user.fullname, user.first_name, user.last_name) == (
        "Existing Name",
        "Existing",
        "Name",
    )
    assert user.email == "existing@example.com"
    assert user.username == "existing"
    changed.assert_not_called()


@pytest.mark.parametrize(
    ("backend_path", "response", "expected"),
    [
        ("google.GoogleOAuth2", {"given_name": "Ada"}, (None, "Ada", None)),
        ("google.GoogleOAuth2", {"given_name": ""}, (None, "", None)),
        ("facebook.FacebookOAuth2", {"last_name": ""}, (None, None, "")),
        (
            "apple.AppleIdAuth",
            {"sub": "123", "_apple_user_name": {"firstName": ""}},
            (None, "", None),
        ),
        ("github.GithubOAuth2", {"name": ""}, ("", None, None)),
        (
            "docker.DockerOAuth2",
            {"full_name": "", "username": "Fallback"},
            ("", None, None),
        ),
        (
            "docker.DockerOAuth2",
            {"full_name": None, "username": "Fallback"},
            ("Fallback", None, None),
        ),
        (
            "yandex.YandexOAuth2",
            {"real_name": "", "display_name": "Fallback"},
            ("", None, None),
        ),
        (
            "yandex.YaruOAuth2",
            {"real_name": None, "display_name": "Fallback"},
            ("Fallback", None, None),
        ),
        (
            "orcid.ORCIDOAuth2",
            {"person": {"name": {"given-names": {"value": ""}}}},
            (None, "", None),
        ),
        (
            "vk.VKontakteOpenAPI",
            {"id": "123", "first_name": [""], "last_name": []},
            (None, "", None),
        ),
        ("kakao.KakaoOAuth2", {"properties": {"nickname": ""}}, ("", None, None)),
        ("kakao.KakaoOAuth2", {"properties": {"nickname": "A"}}, ("A", None, "A")),
    ],
)
def test_name_extraction_distinguishes_missing_and_blank(
    backend_path, response, expected
) -> None:
    backend = module_member(f"social_core.backends.{backend_path}")(
        get_backend({}).strategy
    )
    details = backend.get_user_details(response)
    assert (
        tuple(details.get(key) for key in ("fullname", "first_name", "last_name"))
        == expected
    )
