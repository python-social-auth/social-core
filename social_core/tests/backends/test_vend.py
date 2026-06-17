import json
from typing import cast

import responses

from social_core.exceptions import AuthInvalidParameter
from social_core.tests.models import TestUserSocialAuth, User

from .oauth import OAuth2Test


class VendOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.vend.VendOAuth2"
    expected_username = "victim_shop_a"

    def vend_login(
        self,
        domain_prefix: str,
        username: str,
        email: str,
        vend_id: int = 7,
    ) -> User:
        self.strategy.set_request_data({"domain_prefix": domain_prefix}, self.backend)
        self.access_token_body = json.dumps(
            {
                "access_token": f"{domain_prefix}-token",
                "refresh_token": f"{domain_prefix}-refresh-token",
            }
        )
        self.user_data_url = f"https://{domain_prefix}.vendhq.com/api/users"
        self.user_data_body = json.dumps(
            {
                "users": [
                    {
                        "id": vend_id,
                        "username": username,
                        "email": email,
                    }
                ]
            }
        )
        return cast("User", self.do_start())

    def test_login(self) -> None:
        user = self.vend_login("shop-a", "victim_shop_a", "victim@example.com")

        self.assertEqual(user.username, "victim_shop_a")
        self.assertEqual(len(user.social), 1)
        social = user.social[0]
        self.assertEqual(social.uid, "shop-a:7")
        self.assertEqual(social.extra_data["domain_prefix"], "shop-a")
        self.assertEqual(social.extra_data["refresh_token"], "shop-a-refresh-token")

        request_urls = [call.request.url for call in responses.calls]
        self.assertIn("https://shop-a.vendhq.com/api/1.0/token", request_urls)
        self.assertIn("https://shop-a.vendhq.com/api/users", request_urls)

    def test_same_numeric_id_from_different_shops_creates_new_association(self) -> None:
        victim = self.vend_login("shop-a", "victim_shop_a", "victim@example.com")
        attacker = self.vend_login("shop-b", "attacker_shop_b", "attacker@example.com")

        self.assertIsNot(attacker, victim)
        self.assertEqual(attacker.username, "attacker_shop_b")
        self.assertEqual(len(User.cache), 2)
        self.assertEqual(victim.social[0].uid, "shop-a:7")
        self.assertEqual(attacker.social[0].uid, "shop-b:7")
        self.assertIs(
            TestUserSocialAuth.get_social_auth("vend", "shop-a:7").user,
            victim,
        )
        self.assertIs(
            TestUserSocialAuth.get_social_auth("vend", "shop-b:7").user,
            attacker,
        )

    def test_migrates_matching_legacy_association(self) -> None:
        victim = User("victim_shop_a", email="victim@example.com")
        legacy_social = TestUserSocialAuth(
            victim,
            "vend",
            "7",
            extra_data={"domain_prefix": "shop-a"},
        )

        user = self.vend_login("shop-a", "victim_shop_a", "victim@example.com")

        self.assertIs(user, victim)
        self.assertEqual(len(User.cache), 1)
        self.assertEqual(legacy_social.uid, "shop-a:7")
        self.assertIsNone(TestUserSocialAuth.get_social_auth("vend", "7"))
        self.assertIs(
            TestUserSocialAuth.get_social_auth("vend", "shop-a:7"),
            legacy_social,
        )

    def test_does_not_migrate_mismatched_legacy_association(self) -> None:
        victim = User("victim_shop_a", email="victim@example.com")
        legacy_social = TestUserSocialAuth(
            victim,
            "vend",
            "7",
            extra_data={"domain_prefix": "shop-a"},
        )

        attacker = self.vend_login("shop-b", "attacker_shop_b", "attacker@example.com")

        self.assertIsNot(attacker, victim)
        self.assertEqual(len(User.cache), 2)
        self.assertEqual(legacy_social.uid, "7")
        self.assertIs(
            TestUserSocialAuth.get_social_auth("vend", "7"),
            legacy_social,
        )
        self.assertEqual(attacker.social[0].uid, "shop-b:7")

    def test_rejects_invalid_domain_prefix(self) -> None:
        self.strategy.set_request_data(
            {"domain_prefix": "shop-a.example"}, self.backend
        )

        with self.assertRaises(AuthInvalidParameter):
            self.backend.access_token_url()
