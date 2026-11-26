"""EVE Online sign-in and character transfer account binding."""

from __future__ import annotations

import json
from typing import cast

import responses

from social_core.exceptions import AuthAssociationError, AuthResponseError
from social_core.pipeline.social_auth import load_extra_data, social_user
from social_core.tests.models import TestUserSocialAuth, User

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

CHARACTER = {
    "CharacterID": 95465499,
    "CharacterName": "Traded Pilot",
    "ExpiresOn": "2030-01-01T00:00:00",
    "Scopes": "",
    "TokenType": "Character",
    "CharacterOwnerHash": "seller-hash",
}


class EVEOnlineOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.eveonline.EVEOnlineOAuth2"
    user_data_url = "https://login.eveonline.com/oauth/verify"
    expected_username = "TradedPilot"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "Bearer",
            "expires_in": 1200,
            "refresh_token": "refresh",
        }
    )
    user_data_body = json.dumps(CHARACTER)

    def eve_login(self, owner_hash: object = "seller-hash") -> User:
        responses.reset()
        self.user_data_body = json.dumps(dict(CHARACTER, CharacterOwnerHash=owner_hash))
        return cast("User", self.do_start())

    def test_login_records_owner_hash(self) -> None:
        user = self.eve_login()

        self.assertEqual(len(user.social), 1)
        social = user.social[0]
        self.assertEqual((social.uid, social.id_key), ("95465499", "CharacterID"))
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")

    def test_same_owner_logs_in_again(self) -> None:
        seller = self.eve_login()

        self.assertIs(self.eve_login(), seller)
        self.assertEqual(len(User.cache), 1)

    def test_transferred_character_cannot_authenticate_previous_owner(self) -> None:
        seller = self.eve_login()

        with self.assertRaises(AuthAssociationError) as caught:
            self.eve_login("buyer-hash")

        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertEqual(caught.exception.stage, "pipeline")
        self.assertEqual(len(User.cache), 1)
        social = TestUserSocialAuth.get_social_auth("eveonline", "95465499")
        assert social is not None
        self.assertIs(social.user, seller)
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")

    def test_unkeyed_legacy_association_also_rejects_transfer(self) -> None:
        seller = User("Traded Pilot")
        social = TestUserSocialAuth(
            seller,
            "eveonline",
            "95465499",
            extra_data={"owner_hash": "seller-hash"},
        )

        with self.assertRaises(AuthAssociationError):
            self.eve_login("buyer-hash")

        self.assertIs(social.user, seller)
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")

    def test_association_created_after_identifier_step_rejects_transfer(self) -> None:
        # A paused pipeline resumes with the identifier and response it saved.
        buyer = self.eve_login("buyer-hash")
        social = buyer.social[0]

        with self.assertRaises(AuthAssociationError) as caught:
            social_user(
                self.backend, "95465499", id_key="CharacterID", response=CHARACTER
            )

        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertEqual(caught.exception.claim, "CharacterOwnerHash")
        with self.assertRaises(AuthAssociationError):
            load_extra_data(self.backend, {}, CHARACTER, "95465499")
        with self.assertRaises(AuthAssociationError):
            load_extra_data(self.backend, {}, CHARACTER, "95465499", social=social)
        self.assertIs(social.user, buyer)
        self.assertEqual(social.extra_data["owner_hash"], "buyer-hash")

    def test_legacy_identifier_association_also_rejects_transfer(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_EVEONLINE_LEGACY_ID_KEYS": ["CharacterName"]}
        )
        seller = User("Traded Pilot")
        social = TestUserSocialAuth(
            seller,
            "eveonline",
            "Traded Pilot",
            extra_data={"CharacterID": 95465499, "owner_hash": "seller-hash"},
            id_key="CharacterName",
        )

        with self.assertRaises(AuthAssociationError) as caught:
            self.eve_login("buyer-hash")

        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertEqual((social.uid, social.id_key), ("Traded Pilot", "CharacterName"))
        self.assertIs(social.user, seller)
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")

    def test_legacy_association_without_hash_records_next_owner(self) -> None:
        seller = User("Traded Pilot")
        social = TestUserSocialAuth(
            seller,
            "eveonline",
            "95465499",
            extra_data={"id": 95465499},
            id_key="CharacterID",
        )

        self.assertIs(self.eve_login(), seller)
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")

    def test_get_all_extra_data_rejects_transfer(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GET_ALL_EXTRA_DATA": True})
        seller = self.eve_login()
        social = seller.social[0]
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")
        self.assertEqual(social.extra_data["CharacterOwnerHash"], "seller-hash")

        with self.assertRaises(AuthAssociationError) as caught:
            self.eve_login("buyer-hash")

        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertEqual(social.extra_data["owner_hash"], "seller-hash")

    def test_conflicting_saved_owner_alias_rejects_login(self) -> None:
        owner = User("Traded Pilot")
        social = TestUserSocialAuth(
            owner,
            "eveonline",
            "95465499",
            extra_data={
                "owner_hash": "buyer-hash",
                "CharacterOwnerHash": "seller-hash",
            },
        )
        with self.assertRaises(AuthAssociationError) as caught:
            self.eve_login("buyer-hash")
        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertIs(social.user, owner)

    def test_association_with_raw_owner_hash_rejects_transfer(self) -> None:
        seller = User("Traded Pilot")
        social = TestUserSocialAuth(
            seller,
            "eveonline",
            "95465499",
            extra_data={"CharacterID": 95465499, "CharacterOwnerHash": "seller-hash"},
            id_key="CharacterID",
        )

        with self.assertRaises(AuthAssociationError):
            self.eve_login("buyer-hash")

        self.assertIs(social.user, seller)
        self.assertEqual(social.extra_data["CharacterOwnerHash"], "seller-hash")

    def test_missing_owner_hash_is_rejected_before_association(self) -> None:
        with self.assertRaises(AuthResponseError) as caught:
            self.eve_login(None)

        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertEqual(caught.exception.claim, "CharacterOwnerHash")
        self.assertEqual(len(User.cache), 0)

    def test_missing_owner_hash_does_not_change_existing_association(self) -> None:
        seller = self.eve_login()

        with self.assertRaises(AuthResponseError):
            self.eve_login(" ")

        self.assertEqual(len(User.cache), 1)
        self.assertEqual(seller.social[0].extra_data["owner_hash"], "seller-hash")
