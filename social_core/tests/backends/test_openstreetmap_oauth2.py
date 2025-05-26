import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class OpenStreetMapOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.openstreetmap_oauth2.OpenStreetMapOAuth2"
    user_data_url = "https://api.openstreetmap.org/api/0.6/user/details.json"
    expected_username = "Steve"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "version": "0.6",
            "generator": "OpenStreetMap server",
            "copyright": "OpenStreetMap and contributors",
            "attribution": "http://www.openstreetmap.org/copyright",
            "license": "http://opendatacommons.org/licenses/odbl/1-0/",
            "user": {
                "id": 1,
                "display_name": "Steve",
                "account_created": "2005-09-13T15:32:57Z",
            },
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
