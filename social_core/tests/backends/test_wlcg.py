import json

from social_core.pipeline.social_auth import social_uid

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class WLCGOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.wlcg.WLCGOAuth2"
    user_data_url = "https://wlcg.cloud.cnaf.infn.it/userinfo"
    expected_username = "foo@bar.com"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
        }
    )
    user_data_body = json.dumps(
        {
            "sub": "248289761001",
            "email": "foo@bar.com",
            "family_name": "Bar",
            "given_name": "Foo",
            "name": "Foo Bar",
            "email_verified": True,
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key), ("248289761001", "sub")
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_distinct_subjects_have_distinct_identifiers(self) -> None:
        identifiers = [
            social_uid(self.backend, {}, {"sub": subject})["uid"]
            for subject in ("248289761001", "248289761002")
        ]
        self.assertEqual(identifiers, ["248289761001", "248289761002"])
