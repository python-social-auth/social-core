import time
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock, patch

import requests
import responses
import shopify

from social_core.actions import do_auth, do_complete
from social_core.exceptions import (
    AuthAssociationError,
    AuthInputError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import (
    PARTIAL_TOKEN_SESSION_NAME,
    get_querystring,
    url_add_parameters,
)

from .base import BaseBackendTest

if TYPE_CHECKING:
    from social_core.strategy import HttpResponseProtocol

SHOP = "example.myshopify.com"
ACCESS_TOKEN = "shopify-access-token"
KEY = "a-key"
SECRET = "a-secret-key"


class ShopifyOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.shopify.ShopifyOAuth2"

    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_request_data({"shop": SHOP}, self.backend)

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_SHOPIFY_KEY": KEY,
            "SOCIAL_AUTH_SHOPIFY_SECRET": SECRET,
            "SOCIAL_AUTH_SHOPIFY_SCOPE": ["read_products", "read_customers"],
            "SOCIAL_AUTH_LOGIN_REDIRECT_URL": "/done",
        }

    def signed_callback_data(self, state: str | None) -> dict[str, str]:
        data = {
            "code": "foobar",
            "shop": SHOP,
            "timestamp": str(int(time.time())),
        }
        if state is not None:
            data["state"] = state

        shopify.Session.setup(api_key=KEY, secret=SECRET)
        data["hmac"] = shopify.Session.calculate_hmac(data)
        return data

    def start_for_user(self, user: User) -> str:
        return get_querystring(do_auth(self.backend, user=user).url)["state"]

    def prepare_callback(self, user: User) -> None:
        state = self.start_for_user(user)
        self.strategy.set_request_data(self.signed_callback_data(state), self.backend)

    def complete_through_redirect(self, user: User):
        start_url = do_auth(self.backend, user=user).url
        state = get_querystring(start_url)["state"]
        target_data = self.signed_callback_data(state)
        target_url = url_add_parameters(
            self.strategy.build_absolute_uri(self.complete_url), target_data
        )

        responses.add(
            responses.GET,
            start_url,
            status=301,
            headers={"Location": target_url},
        )
        responses.add(responses.GET, target_url, status=200, body="foobar")

        response = requests.get(start_url, timeout=1)
        self.assertEqual(response.url, target_url)
        self.assertEqual(response.text, "foobar")
        self.strategy.set_request_data(target_data, self.backend)
        return do_complete(self.backend, login=Mock(), user=user)

    def test_auth_url_contains_state_parameter(self) -> None:
        user = User("existing")
        start_url = do_auth(self.backend, user=user).url
        query = get_querystring(start_url)
        state = query.get("state")

        self.assertTrue(start_url.startswith(f"https://{SHOP}/admin/oauth/authorize?"))
        self.assertIsNotNone(state)
        self.assertEqual(query["client_id"], "a-key")
        self.assertEqual(query["scope"], "read_products,read_customers")
        self.assertEqual(query["redirect_uri"], "http://myapp.com")
        context = self.strategy.session_get("shopify_state")
        assert isinstance(context, dict)
        self.assertEqual(context["state"], state)
        self.assertEqual(context["user_id"], str(user.id))

    def test_auth_url_requires_shop(self) -> None:
        self.strategy.remove_from_request_data("shop")
        with self.assertRaises(AuthInputError):
            do_auth(self.backend, user=User("existing"))

    def test_start_requires_authenticated_user(self) -> None:
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend)
        anonymous = User("anonymous")
        cast(Any, anonymous).is_authenticated = False
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend, user=anonymous)
        self.assertIsNone(self.strategy.session_get("shopify_state"))

    def test_direct_start_requires_prepared_context(self) -> None:
        with self.assertRaises(AuthSessionError):
            self.backend.start()

    def test_auth_url_normalizes_shop(self) -> None:
        user = User("existing")
        for shop in ("example", "https://Example.myshopify.com/", "example.org"):
            with self.subTest(shop=shop):
                self.strategy.set_request_data({"shop": shop}, self.backend)
                self.assertTrue(
                    do_auth(self.backend, user=user).url.startswith(
                        f"https://{SHOP}/admin/oauth/authorize?"
                    )
                )

    def test_auth_url_rejects_invalid_shop(self) -> None:
        user = User("existing")
        for shop in (
            "evil%2eexample\\",
            "3232235777\\",
            "exam ple",
            "exam_ple",
            "-example",
            "[::1]",
            "[",
            ".",
        ):
            with self.subTest(shop=shop):
                self.strategy.set_request_data({"shop": shop}, self.backend)
                with self.assertRaises(AuthInputError) as caught:
                    do_auth(self.backend, user=user)
                self.assertEqual(caught.exception.code, "invalid_parameter")
                self.assertEqual(caught.exception.parameter, "shop")
                self.assertEqual(caught.exception.stage, "begin")

    def test_new_start_replaces_previous_state(self) -> None:
        user = User("existing")
        first_state = self.start_for_user(user)
        second_state = self.start_for_user(user)
        self.assertNotEqual(first_state, second_state)

        self.strategy.set_request_data(
            self.signed_callback_data(first_state), self.backend
        )
        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

    def test_complete_rejects_missing_state_parameter(self) -> None:
        user = User("existing")
        self.start_for_user(user)
        self.strategy.set_request_data(self.signed_callback_data(None), self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete(user=user)

    def test_complete_rejects_mismatched_state_parameter(self) -> None:
        user = User("existing")
        self.start_for_user(user)
        self.strategy.set_request_data(
            self.signed_callback_data("invalid-state"), self.backend
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

    def test_complete_rejects_logged_out_or_different_user(self) -> None:
        user = User("existing")
        for current_user in (None, User("other")):
            with self.subTest(user=current_user):
                self.prepare_callback(user)
                with (
                    patch.object(shopify.Session, "request_token") as request_token,
                    self.assertRaises(AuthSessionError),
                ):
                    self.backend.complete(user=current_user)
                request_token.assert_not_called()
        self.assertEqual(user.social, [])

    def test_association(self) -> None:
        user = User("existing")
        self.prepare_callback(user)
        login = Mock()
        with patch.object(shopify.Session, "request_token", return_value=ACCESS_TOKEN):
            do_complete(self.backend, login=login, user=user)

        login.assert_not_called()
        self.assertEqual(len(User.cache), 1)
        self.assertEqual(user.username, "existing")
        social = TestUserSocialAuth.get_social_auth("shopify", SHOP)
        assert social is not None
        self.assertIs(social.user, user)
        self.assertEqual(social.extra_data["access_token"], ACCESS_TOKEN)
        self.assertIsNone(self.strategy.session_get("shopify_state"))

    def test_shop_association_cannot_authenticate_another_user(self) -> None:
        # Everyone who may approve the app on a store presents the same shop.
        owner = User("owner")
        social = TestUserSocialAuth.create_social_auth(owner, SHOP, "shopify")

        with self.assertRaises(AuthSessionError):
            do_auth(self.backend)
        self.strategy.set_request_data(
            self.signed_callback_data("forged"), self.backend
        )
        with self.assertRaises(AuthSessionError):
            self.backend.complete()

        other = User("other")
        self.prepare_callback(other)
        with (
            patch.object(shopify.Session, "request_token", return_value=ACCESS_TOKEN),
            self.assertRaises(AuthAssociationError),
        ):
            self.backend.complete(user=other)
        self.assertIs(social.user, owner)
        self.assertEqual(other.social, [])

    def test_association_exchanges_token_with_shopify_api(self) -> None:
        user = User("existing")
        self.prepare_callback(user)
        with patch.object(
            shopify.Session, "request_token", return_value=ACCESS_TOKEN
        ) as request_token:
            self.assertIs(self.backend.complete(user=user), user)

        request_token.assert_called_once()
        token_data = cast("dict[str, str]", request_token.call_args.args[0])
        self.assertEqual(token_data["code"], "foobar")
        self.assertEqual(token_data["shop"], SHOP)
        self.assertEqual(token_data["state"], self.backend.data["state"])

    def test_invalid_callback_signature_is_not_cancellation(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        data = self.signed_callback_data(state)
        data["hmac"] = "invalid"
        self.strategy.set_request_data(data, self.backend)
        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthResponseError) as caught,
        ):
            self.backend.complete(user=user)
        self.assertEqual(caught.exception.code, "invalid_signature")
        self.assertEqual(caught.exception.stage, "callback")
        self.assertEqual(caught.exception.recovery, "contact_administrator")
        authenticate.assert_not_called()

    def test_complete_rejects_invalid_shop(self) -> None:
        user = User("existing")
        data = self.signed_callback_data(self.start_for_user(user))
        data["shop"] = "evil%2eexample\\"
        data["hmac"] = shopify.Session.calculate_hmac(data)
        self.strategy.set_request_data(data, self.backend)
        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthInputError) as caught,
        ):
            self.backend.complete(user=user)
        self.assertEqual(caught.exception.code, "invalid_parameter")
        self.assertEqual(caught.exception.parameter, "shop")
        self.assertEqual(caught.exception.stage, "callback")
        authenticate.assert_not_called()

    def test_sdk_callback_validation_failure_is_invalid_input(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        self.strategy.set_request_data(self.signed_callback_data(state), self.backend)
        cause = shopify.ValidationException("private validation details")
        with (
            patch.object(shopify, "Session", side_effect=cause) as session,
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthInputError) as caught,
        ):
            # Validation reached Session construction after a valid signature.
            session.validate_hmac.return_value = True
            self.backend.complete(user=user)
        self.assertEqual(caught.exception.code, "invalid_parameter")
        self.assertEqual(caught.exception.stage, "callback")
        self.assertIs(caught.exception.__cause__, cause)
        authenticate.assert_not_called()

    def test_sdk_token_validation_failure_is_invalid_input(self) -> None:
        data = self.signed_callback_data(None)
        data["timestamp"] = str(int(time.time()) - 48 * 60 * 60)
        data["hmac"] = shopify.Session.calculate_hmac(data)
        with self.assertRaises(AuthInputError) as caught:
            self.backend.extra_data(
                None, SHOP, {"shop": SHOP, "access_token": data}, {}, {}
            )
        self.assertEqual(caught.exception.code, "invalid_parameter")
        self.assertEqual(caught.exception.stage, "callback")
        self.assertIsInstance(caught.exception.__cause__, shopify.ValidationException)

    def test_partial_pipeline_with_new_requests(self) -> None:
        self.pipeline_settings()
        existing = User("existing")
        with patch.object(
            shopify.Session, "request_token", autospec=True, return_value=ACCESS_TOKEN
        ) as request_token:
            result = self.complete_through_redirect(existing)
            for step, value, request_data in (
                ("password", "foobar", {}),
                ("slug", "foo-bar", {"shop": "other.myshopify.com"}),
            ):
                self.assertEqual(
                    cast("HttpResponseProtocol", result).url,
                    self.strategy.build_absolute_uri(f"/{step}"),
                )
                token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
                self.strategy.session_set(step, value)
                result = self.resume_partial_with_new_request(token, request_data)

        user = cast("User", result)
        self.assertIs(user, existing)
        self.assertEqual(user.social[0].extra_data["shop"], SHOP)
        self.assertEqual(user.social[0].extra_data["access_token"], ACCESS_TOKEN)
        self.assertEqual(user.password, "foobar")
        self.assertEqual(user.slug, "foo-bar")
        self.assertEqual(request_token.call_count, 1)
        self.assertEqual(request_token.call_args_list[0].args[1]["shop"], SHOP)
        self.assertEqual(request_token.call_args_list[0].args[0].url, SHOP)

    def test_extra_data_requires_saved_shop(self) -> None:
        with self.assertRaises(AuthInputError):
            self.backend.extra_data(None, SHOP, {"access_token": ACCESS_TOKEN}, {}, {})
