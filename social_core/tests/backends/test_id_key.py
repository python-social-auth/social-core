from types import SimpleNamespace
from typing import Any
from unittest import TestCase
from unittest.mock import Mock

from social_core.exceptions import AuthMissingParameter
from social_core.tests.models import TestStorage, TestUserSocialAuth, User
from social_core.tests.strategy import TestStrategy
from social_core.utils import module_member, setting_name


class ConfigurableIdKeyTest(TestCase):
    direct_response_backends = (
        "social_core.backends.azuread.AzureADOAuth2",
        "social_core.backends.azuread_b2c.AzureADB2COAuth2",
        "social_core.backends.azuread_tenant.AzureADTenantOAuth2",
        "social_core.backends.azuread_tenant.AzureADV2TenantOAuth2",
        "social_core.backends.classlink.ClasslinkOAuth",
        "social_core.backends.discourse.DiscourseAuth",
        "social_core.backends.flat.FlatOAuth2",
        "social_core.backends.kakao.KakaoOAuth2",
        "social_core.backends.kick.KickOAuth2",
        "social_core.backends.lastfm.LastFmAuth",
        "social_core.backends.mapmyfitness.MapMyFitnessOAuth2",
        "social_core.backends.mendeley.MendeleyOAuth2",
        "social_core.backends.microsoft.MicrosoftOAuth2",
        "social_core.backends.naver.NaverOAuth2",
        "social_core.backends.orbi.OrbiOAuth2",
        "social_core.backends.open_id_connect.OpenIdConnectAuth",
        "social_core.backends.qiita.QiitaOAuth2",
        "social_core.backends.twitch.TwitchOAuth2",
    )
    details_backends = (
        "social_core.backends.auth0.Auth0OAuth2",
        "social_core.backends.cas.CASOpenIdConnectAuth",
        "social_core.backends.mediawiki.MediaWiki",
        "social_core.backends.suse.OpenSUSEOpenId",
        "social_core.backends.ubuntu.UbuntuOpenId",
        "social_core.backends.yandex.YandexOpenId",
    )
    nested_response_backends = (
        ("social_core.backends.behance.BehanceOAuth2", ("user",)),
        ("social_core.backends.clever.CleverOAuth2", ("data",)),
        ("social_core.backends.coinbase.CoinbaseOAuth2", ("data",)),
        ("social_core.backends.digitalocean.DigitalOceanOAuth", ("account",)),
        ("social_core.backends.disqus.DisqusOAuth2", ("response",)),
        ("social_core.backends.foursquare.FoursquareOAuth2", ("response", "user")),
        ("social_core.backends.goclio.GoClioOAuth2", ("user",)),
        ("social_core.backends.instagram.InstagramOAuth2", ("user",)),
        ("social_core.backends.openshift.OpenshiftOAuth2", ("metadata",)),
        ("social_core.backends.podio.PodioOAuth2", ("ref",)),
        ("social_core.backends.stocktwits.StocktwitsOAuth2", ("user",)),
        ("social_core.backends.strava.StravaOAuth", ("athlete",)),
        ("social_core.backends.tumblr.TumblrOAuth", ("response", "user")),
        ("social_core.backends.universe.UniverseOAuth2", ("current_user",)),
        ("social_core.backends.untappd.UntappdOAuth2", ("user",)),
        ("social_core.backends.vimeo.VimeoOAuth1", ("person",)),
        ("social_core.backends.yammer.YammerOAuth2", ("user",)),
    )
    explicit_default_keys = (
        ("social_core.backends.auth0.Auth0OAuth2", "user_id"),
        ("social_core.backends.azuread.AzureADOAuth2", "upn"),
        ("social_core.backends.azuread_b2c.AzureADB2COAuth2", "sub"),
        ("social_core.backends.azuread_tenant.AzureADTenantOAuth2", "sub"),
        (
            "social_core.backends.azuread_tenant.AzureADV2TenantOAuth2",
            "preferred_username",
        ),
        ("social_core.backends.cas.CASOpenIdConnectAuth", "username"),
        ("social_core.backends.cilogon.CILogonOAuth2", "sub"),
        ("social_core.backends.classlink.ClasslinkOAuth", "UserId"),
        ("social_core.backends.digitalocean.DigitalOceanOAuth", "uuid"),
        ("social_core.backends.discourse.DiscourseAuth", "email"),
        ("social_core.backends.drip.DripOAuth", "email"),
        ("social_core.backends.google.GoogleOAuth2", "email"),
        ("social_core.backends.kick.KickOAuth2", "user_id"),
        ("social_core.backends.lastfm.LastFmAuth", "name"),
        ("social_core.backends.mediawiki.MediaWiki", "userID"),
        ("social_core.backends.openshift.OpenshiftOAuth2", "uid"),
        ("social_core.backends.pushbullet.PushbulletOAuth2", "iden"),
        ("social_core.backends.qiita.QiitaOAuth2", "id"),
        ("social_core.backends.suse.OpenSUSEOpenId", "nickname"),
        ("social_core.backends.twitch.TwitchOAuth2", "id"),
        ("social_core.backends.ubuntu.UbuntuOpenId", "nickname"),
        ("social_core.backends.vimeo.VimeoOAuth2", "uri"),
        ("social_core.backends.yandex.YandexOpenId", "email"),
        ("social_core.backends.zotero.ZoteroOAuth", "userID"),
    )
    required_default_id_backends = (
        "social_core.backends.classlink.ClasslinkOAuth",
        "social_core.backends.discourse.DiscourseAuth",
        "social_core.backends.flat.FlatOAuth2",
        "social_core.backends.kakao.KakaoOAuth2",
        "social_core.backends.kick.KickOAuth2",
        "social_core.backends.lastfm.LastFmAuth",
        "social_core.backends.mapmyfitness.MapMyFitnessOAuth2",
        "social_core.backends.mendeley.MendeleyOAuth2",
        "social_core.backends.microsoft.MicrosoftOAuth2",
        "social_core.backends.naver.NaverOAuth2",
        "social_core.backends.twitch.TwitchOAuth2",
    )

    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()

    def backend(self, path: str, **settings):
        strategy = TestStrategy(TestStorage)
        backend_class = module_member(path)
        backend = backend_class(strategy)
        strategy.set_settings(
            {
                setting_name(backend.name, name): value
                for name, value in settings.items()
            }
        )
        return backend

    def test_direct_response_overrides_use_configured_key(self) -> None:
        for path in self.direct_response_backends:
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY="custom_id")
                self.assertEqual(
                    backend.get_user_id({}, {"custom_id": "configured"}),
                    "configured",
                )

    def test_details_overrides_use_configured_key(self) -> None:
        for path in self.details_backends:
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY="custom_id")
                self.assertEqual(
                    backend.get_user_id(
                        {"custom_id": "configured"},
                        SimpleNamespace(identity_url="https://example.com/user"),
                    ),
                    "configured",
                )

    def test_nested_response_overrides_use_configured_key(self) -> None:
        for path, container_path in self.nested_response_backends:
            with self.subTest(path=path):
                response: dict[str, Any] = {"custom_id": "configured"}
                for container in reversed(container_path):
                    response = {container: response}
                backend = self.backend(path, ID_KEY="custom_id")
                self.assertEqual(backend.get_user_id({}, response), "configured")

    def test_mapping_overrides_use_normalized_details(self) -> None:
        cases: tuple[tuple[str, str, dict[str, Any]], ...] = (
            (
                "social_core.backends.azuread_tenant.AzureADV2TenantOAuth2",
                "email",
                {},
            ),
            (
                "social_core.backends.behance.BehanceOAuth2",
                "fullname",
                {"user": {}},
            ),
            (
                "social_core.backends.bitbucket.BitbucketOAuth2",
                "fullname",
                {},
            ),
            (
                "social_core.backends.clever.CleverOAuth2",
                "username",
                {"data": {}},
            ),
            (
                "social_core.backends.coinbase.CoinbaseOAuth2",
                "fullname",
                {"data": {}},
            ),
            (
                "social_core.backends.digitalocean.DigitalOceanOAuth",
                "username",
                {"account": {}},
            ),
            (
                "social_core.backends.disqus.DisqusOAuth2",
                "user_id",
                {"response": {}},
            ),
            (
                "social_core.backends.foursquare.FoursquareOAuth2",
                "email",
                {"response": {"user": {}}},
            ),
            (
                "social_core.backends.goclio.GoClioOAuth2",
                "username",
                {"user": {}},
            ),
            (
                "social_core.backends.instagram.InstagramOAuth2",
                "fullname",
                {"user": {}},
            ),
            (
                "social_core.backends.openshift.OpenshiftOAuth2",
                "username",
                {"metadata": {}},
            ),
            (
                "social_core.backends.podio.PodioOAuth2",
                "email",
                {"ref": {}, "user": {}},
            ),
            (
                "social_core.backends.qiita.QiitaOAuth2",
                "fullname",
                {},
            ),
            (
                "social_core.backends.stocktwits.StocktwitsOAuth2",
                "fullname",
                {"user": {}},
            ),
            (
                "social_core.backends.strava.StravaOAuth",
                "first_name",
                {"athlete": {}},
            ),
            (
                "social_core.backends.tumblr.TumblrOAuth",
                "username",
                {"response": {"user": {}}},
            ),
            (
                "social_core.backends.universe.UniverseOAuth2",
                "username",
                {"current_user": {}},
            ),
            (
                "social_core.backends.untappd.UntappdOAuth2",
                "fullname",
                {"user": {}},
            ),
            (
                "social_core.backends.vimeo.VimeoOAuth1",
                "fullname",
                {"person": {}},
            ),
            (
                "social_core.backends.vimeo.VimeoOAuth2",
                "fullname",
                {"user": {}},
            ),
            (
                "social_core.backends.yammer.YammerOAuth2",
                "email",
                {"user": {}, "access_token": {}},
            ),
        )
        for path, id_key, response in cases:
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY=id_key)
                self.assertEqual(
                    backend.get_user_id({id_key: "configured"}, response),
                    "configured",
                )

    def test_podio_uses_configured_user_field(self) -> None:
        backend = self.backend(
            "social_core.backends.podio.PodioOAuth2", ID_KEY="user_id"
        )

        self.assertEqual(
            backend.get_user_id({}, {"ref": {}, "user": {"user_id": 123}}),
            123,
        )

    def test_disqus_uses_configured_token_field(self) -> None:
        backend = self.backend(
            "social_core.backends.disqus.DisqusOAuth2", ID_KEY="user_id"
        )

        self.assertEqual(
            backend.get_user_id({}, {"response": {}, "user_id": 123}),
            123,
        )

    def test_kakao_uses_configured_properties_field(self) -> None:
        backend = self.backend(
            "social_core.backends.kakao.KakaoOAuth2", ID_KEY="nickname"
        )

        self.assertEqual(
            backend.get_user_id(
                {"username": "configured"},
                {"id": 123, "properties": {"nickname": "configured"}},
            ),
            "configured",
        )

    def test_yammer_uses_configured_token_field(self) -> None:
        backend = self.backend(
            "social_core.backends.yammer.YammerOAuth2", ID_KEY="user_id"
        )

        self.assertEqual(
            backend.get_user_id({}, {"user": {}, "access_token": {"user_id": 123}}),
            123,
        )

    def test_declared_default_keys_match_existing_identifiers(self) -> None:
        for path, expected in self.explicit_default_keys:
            with self.subTest(path=path):
                self.assertEqual(self.backend(path).ID_KEY, expected)

    def test_lookup_rejects_missing_default_id(self) -> None:
        for path in self.required_default_id_backends:
            with self.subTest(path=path):
                backend = self.backend(path)
                with self.assertRaisesRegex(AuthMissingParameter, backend.ID_KEY):
                    backend.get_user_id({}, {})

    def test_inherited_lookup_uses_normalized_details(self) -> None:
        backend = self.backend(
            "social_core.backends.mendeley.MendeleyOAuth2",
            ID_KEY="profile_id",
        )

        self.assertEqual(
            backend.get_user_id({"profile_id": "configured"}, {"id": "provider"}),
            "configured",
        )

    def test_configured_key_wins_over_legacy_selectors(self) -> None:
        cases = (
            (
                "social_core.backends.bitbucket.BitbucketOAuth2",
                "USERNAME_AS_ID",
                {"custom_id": "configured", "username": "legacy"},
            ),
            (
                "social_core.backends.google.GoogleOAuth2",
                "USE_UNIQUE_USER_ID",
                {"custom_id": "configured", "sub": "legacy"},
            ),
            (
                "social_core.backends.qiita.QiitaOAuth2",
                "IDENTIFIED_BY_PERMANENT_ID",
                {"custom_id": "configured", "permanent_id": "legacy"},
            ),
        )
        for path, legacy_setting, response in cases:
            with self.subTest(path=path):
                backend = self.backend(
                    path,
                    ID_KEY="custom_id",
                    **{legacy_setting: True},
                )
                self.assertEqual(backend.get_user_id({}, response), "configured")

    def test_legacy_selectors_apply_without_configured_key(self) -> None:
        cases = (
            (
                "social_core.backends.bitbucket.BitbucketOAuth2",
                "USERNAME_AS_ID",
                {"uuid": "default", "username": "legacy"},
                "legacy",
            ),
            (
                "social_core.backends.google.GoogleOAuth2",
                "USE_UNIQUE_USER_ID",
                {"sub": "legacy"},
                "legacy",
            ),
            (
                "social_core.backends.qiita.QiitaOAuth2",
                "IDENTIFIED_BY_PERMANENT_ID",
                {"id": "default", "permanent_id": 123},
                "123",
            ),
        )
        for path, legacy_setting, response, expected in cases:
            with self.subTest(path=path):
                backend = self.backend(path, **{legacy_setting: True})
                self.assertEqual(backend.get_user_id({}, response), expected)

    def test_google_openidconnect_configured_key_wins_over_legacy_selector(
        self,
    ) -> None:
        backend = self.backend(
            "social_core.backends.google_openidconnect.GoogleOpenIdConnect",
            ID_KEY="custom_id",
            USE_UNIQUE_USER_ID=True,
        )
        backend.id_token = {"sub": "validated-subject"}

        self.assertEqual(
            backend.get_user_id({"custom_id": "configured"}, {}),
            "configured",
        )

    def test_openidconnect_uses_configured_id_token_claim(self) -> None:
        backend = self.backend(
            "social_core.backends.open_id_connect.OpenIdConnectAuth",
            ID_KEY="custom_id",
        )
        backend.id_token = {"custom_id": "token-only-identifier"}

        self.assertEqual(
            backend.get_user_id({}, {}),
            "token-only-identifier",
        )

    def test_auth0_openidconnect_preserves_validated_subject(self) -> None:
        backend = self.backend(
            "social_core.backends.auth0_openidconnect.Auth0OpenIdConnectAuth"
        )
        backend.id_token = {"sub": "validated-subject"}
        self.assertEqual(
            backend.get_user_id({"user_id": "response-subject"}, {}),
            "validated-subject",
        )

        backend = self.backend(
            "social_core.backends.auth0_openidconnect.Auth0OpenIdConnectAuth",
            ID_KEY="custom_id",
        )
        backend.id_token = {"sub": "validated-subject"}
        self.assertEqual(
            backend.get_user_id({"custom_id": "configured"}, {}),
            "configured",
        )

        backend = self.backend(
            "social_core.backends.auth0_openidconnect.Auth0OpenIdConnectAuth"
        )
        self.assertEqual(
            backend.get_user_id({"user_id": "response-subject"}, {}),
            "response-subject",
        )

    def test_composite_overrides_preserve_scoping(self) -> None:
        backend = self.backend(
            "social_core.backends.cilogon.CILogonOAuth2", ID_KEY="custom_id"
        )
        self.assertEqual(
            backend.get_user_id({}, {"custom_id": "configured", "iss": "issuer"}),
            "configured issuer",
        )

        backend = self.backend(
            "social_core.backends.loginradius.LoginRadiusAuth", ID_KEY="custom_id"
        )
        self.assertEqual(
            backend.get_user_id(
                {}, {"custom_id": "configured", "Provider": "provider"}
            ),
            "provider-configured",
        )

        backend = self.backend(
            "social_core.backends.vend.VendOAuth2", ID_KEY="custom_id"
        )
        self.assertEqual(
            backend.get_user_id(
                {},
                {
                    "custom_id": "configured",
                    "domain_prefix": "shop",
                    "id": "legacy",
                },
            ),
            "shop:configured",
        )

    def test_composite_overrides_use_normalized_details(self) -> None:
        cases: tuple[tuple[str, str, dict[str, str], dict[str, str], str], ...] = (
            (
                "social_core.backends.cilogon.CILogonOAuth2",
                "fullname",
                {"fullname": "configured"},
                {"iss": "issuer"},
                "configured issuer",
            ),
            (
                "social_core.backends.loginradius.LoginRadiusAuth",
                "email",
                {"email": "configured"},
                {"Provider": "provider"},
                "provider-configured",
            ),
            (
                "social_core.backends.vend.VendOAuth2",
                "username",
                {"username": "configured"},
                {"domain_prefix": "shop", "id": "legacy"},
                "shop:configured",
            ),
        )
        for path, id_key, details, response, expected in cases:
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY=id_key)
                self.assertEqual(
                    backend.get_user_id(details, response),
                    expected,
                )

    def test_transformed_and_remote_overrides_use_configured_key(self) -> None:
        backend = self.backend(
            "social_core.backends.vimeo.VimeoOAuth2", ID_KEY="custom_id"
        )
        self.assertEqual(
            backend.get_user_id({}, {"user": {"custom_id": "/users/configured"}}),
            "/users/configured",
        )
        backend = self.backend("social_core.backends.vimeo.VimeoOAuth2")
        self.assertEqual(
            backend.get_user_id({}, {"user": {"uri": "/users/default"}}),
            "default",
        )

        backend = self.backend(
            "social_core.backends.pushbullet.PushbulletOAuth2", ID_KEY="custom_id"
        )
        backend.get_json = Mock(return_value={"custom_id": "configured"})
        self.assertEqual(
            backend.get_user_id({"username": b"access-token"}, {}),
            "configured",
        )

    def test_configured_keys_preserve_missing_identifier_validation(self) -> None:
        cases: tuple[tuple[str, dict[str, str]], ...] = (
            ("social_core.backends.azuread.AzureADOAuth2", {}),
            ("social_core.backends.vend.VendOAuth2", {"domain_prefix": "shop"}),
        )
        for path, response in cases:
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY="custom_id")
                with self.assertRaises(AuthMissingParameter):
                    backend.get_user_id({}, response)

    def test_mapping_overrides_reject_missing_configured_key(self) -> None:
        direct_backends = self.direct_response_backends
        details_backends = tuple(
            path
            for path in self.details_backends
            if path != "social_core.backends.yandex.YandexOpenId"
        )
        for path in (*direct_backends, *details_backends):
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY="missing_id")
                with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
                    backend.get_user_id({}, {})

        for path, container_path in self.nested_response_backends:
            with self.subTest(path=path):
                response: dict[str, Any] = {}
                for container in reversed(container_path):
                    response = {container: response}
                backend = self.backend(path, ID_KEY="missing_id")
                with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
                    backend.get_user_id({}, response)

    def test_special_overrides_reject_missing_configured_key(self) -> None:
        cases: tuple[tuple[str, dict[str, Any], dict[str, Any]], ...] = (
            ("social_core.backends.bitbucket.BitbucketOAuth2", {}, {}),
            ("social_core.backends.cilogon.CILogonOAuth2", {}, {"iss": "issuer"}),
            ("social_core.backends.google.GoogleOAuth2", {}, {}),
            (
                "social_core.backends.google_openidconnect.GoogleOpenIdConnect",
                {},
                {},
            ),
            (
                "social_core.backends.auth0_openidconnect.Auth0OpenIdConnectAuth",
                {},
                {},
            ),
            (
                "social_core.backends.loginradius.LoginRadiusAuth",
                {},
                {"Provider": "provider"},
            ),
            ("social_core.backends.qiita.QiitaOAuth2", {}, {}),
            ("social_core.backends.vimeo.VimeoOAuth2", {}, {"user": {}}),
        )
        for path, details, response in cases:
            with self.subTest(path=path):
                backend = self.backend(path, ID_KEY="missing_id")
                with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
                    backend.get_user_id(details, response)

        backend = self.backend(
            "social_core.backends.pushbullet.PushbulletOAuth2",
            ID_KEY="missing_id",
        )
        backend.get_json = Mock(return_value={})
        with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
            backend.get_user_id({"username": b"access-token"}, {})

    def test_yandex_preserves_identity_url_fallback_for_missing_key(self) -> None:
        identity_url = "https://provider.example/users/123"
        backend = self.backend(
            "social_core.backends.yandex.YandexOpenId",
            ID_KEY="missing_id",
        )

        self.assertEqual(
            backend.get_user_id({}, SimpleNamespace(identity_url=identity_url)),
            identity_url,
        )

    def test_protocol_derived_identifiers_ignore_configured_key(self) -> None:
        identity_url = "https://provider.example/users/123"
        backend = self.backend(
            "social_core.backends.open_id.OpenIdAuth", ID_KEY="custom_id"
        )
        self.assertEqual(
            backend.get_user_id({}, SimpleNamespace(identity_url=identity_url)),
            identity_url,
        )

        backend = self.backend(
            "social_core.backends.steam.SteamOpenId", ID_KEY="custom_id"
        )
        steam_url = "https://steamcommunity.com/openid/id/123"
        self.assertEqual(
            backend.get_user_id({}, SimpleNamespace(identity_url=steam_url)),
            "123",
        )

    def test_saml_identifier_uses_idp_mapping(self) -> None:
        try:
            backend = self.backend(
                "social_core.backends.saml.SAMLAuth", ID_KEY="custom_id"
            )
        except ImportError:  # pragma: no cover
            self.skipTest("python3-saml is not installed")
        idp = Mock()
        idp.name = "idp"
        idp.get_user_permanent_id.return_value = "permanent-id"
        backend.get_idp = Mock(return_value=idp)

        self.assertEqual(
            backend.get_user_id(
                {}, {"idp_name": "idp", "attributes": {"custom_id": "ignored"}}
            ),
            "idp:permanent-id",
        )
