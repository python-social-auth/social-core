import time
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import requests
import responses
import shopify

from social_core.exceptions import AuthInputError, AuthSessionError
from social_core.utils import (
    PARTIAL_TOKEN_SESSION_NAME,
    get_querystring,
    url_add_parameters,
)

from .base import BaseBackendTest

if TYPE_CHECKING:
    from social_core.strategy import HttpResponseProtocol
    from social_core.tests.models import User

SHOP = "example.myshopify.com"
ACCESS_TOKEN = "shopify-access-token"
KEY = "a-key"
SECRET = "a-secret-key"


class ShopifyOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.shopify.ShopifyOAuth2"
    expected_username = "example"

    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_request_data({"shop": SHOP}, self.backend)

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_SHOPIFY_KEY": KEY,
            "SOCIAL_AUTH_SHOPIFY_SECRET": SECRET,
            "SOCIAL_AUTH_SHOPIFY_SCOPE": ["read_products", "read_customers"],
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

    def do_start(self):
        start_url = self.backend.start().url
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
        return self.backend.complete()

    def test_auth_url_contains_state_parameter(self) -> None:
        start_url = self.backend.start().url
        query = get_querystring(start_url)
        state = query.get("state")

        self.assertTrue(start_url.startswith(f"https://{SHOP}/admin/oauth/authorize?"))
        self.assertIsNotNone(state)
        self.assertEqual(query["client_id"], "a-key")
        self.assertEqual(query["scope"], "read_products,read_customers")
        self.assertEqual(query["redirect_uri"], "http://myapp.com")
        self.assertEqual(state, self.strategy.session_get("shopify_state"))

    def test_auth_url_requires_shop(self) -> None:
        self.strategy.remove_from_request_data("shop")
        with self.assertRaises(AuthInputError):
            self.backend.start()

    def test_auth_url_reuses_state_for_concurrent_starts(self) -> None:
        first_url = self.backend.start().url
        first_state = get_querystring(first_url)["state"]

        second_url = self.backend.start().url
        second_state = get_querystring(second_url)["state"]

        self.assertEqual(first_state, second_state)
        self.assertEqual(first_state, self.strategy.session_get("shopify_state"))

        self.strategy.set_request_data(
            self.signed_callback_data(first_state), self.backend
        )
        with patch.object(shopify.Session, "request_token", return_value=ACCESS_TOKEN):
            self.backend.complete()

    def test_complete_rejects_missing_state_parameter(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(self.signed_callback_data(None), self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete()

    def test_complete_rejects_mismatched_state_parameter(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            self.signed_callback_data("invalid-state"), self.backend
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete()

    def test_login_exchanges_token_with_shopify_api(self) -> None:
        with patch.object(
            shopify.Session, "request_token", return_value=ACCESS_TOKEN
        ) as request_token:
            self.do_login()

        request_token.assert_called_once()
        token_data = cast("dict[str, str]", request_token.call_args.args[0])
        self.assertEqual(token_data["code"], "foobar")
        self.assertEqual(token_data["shop"], SHOP)
        self.assertEqual(
            token_data["state"], self.strategy.session_get("shopify_state")
        )

    def test_login(self) -> None:
        with patch.object(shopify.Session, "request_token", return_value=ACCESS_TOKEN):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        with patch.object(shopify.Session, "request_token", return_value=ACCESS_TOKEN):
            self.do_partial_pipeline()

    def test_partial_pipeline_with_new_requests(self) -> None:
        self.pipeline_settings()
        with patch.object(
            shopify.Session, "request_token", autospec=True, return_value=ACCESS_TOKEN
        ) as request_token:
            result = self.do_start()
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
