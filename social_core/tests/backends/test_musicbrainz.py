import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class MusicBrainzAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.musicbrainz.MusicBrainzOAuth2"
    user_data_url = "https://musicbrainz.org/oauth2/userinfo"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "GjtKfJS6G4lupbQcCOiTKo4HcLXUgI1p",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "GjSCBBjp4fnbE0AKo3uFu9qq9K2fFm4u",
        }
    )
    user_data_body = json.dumps(
        {
            "sub": "foobar",
            "metabrainz_user_id": 123,
            "email": "foo@bar.com",
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("123", "metabrainz_user_id"),
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
