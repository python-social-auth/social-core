import json

from .oauth import OAuth2Test


class MusicBrainzAuth2Test(OAuth2Test):
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
            "email": "foo@bar.com",
        }
    )

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
