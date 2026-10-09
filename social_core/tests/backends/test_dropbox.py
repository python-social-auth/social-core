import json

from social_core.pipeline.social_auth import social_uid

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class DropboxOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.dropbox.DropboxOAuth2V2"
    user_data_url = "https://api.dropboxapi.com/2/users/get_current_account"
    user_data_url_post = True
    expected_username = "dbidAAH4f99T0taONIb-OurWxbNQ6ywGRopQngc"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
            "name": {
                "given_name": "Franz",
                "surname": "Ferdinand",
                "familiar_name": "Franz",
                "display_name": "Franz Ferdinand (Personal)",
                "abbreviated_name": "FF",
            },
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc", "account_id"),
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_distinct_accounts_have_distinct_identifiers(self) -> None:
        identifiers = [
            social_uid(self.backend, {}, {"account_id": account_id})["uid"]
            for account_id in ("dbid:first", "dbid:second")
        ]
        self.assertEqual(identifiers, ["dbid:first", "dbid:second"])
