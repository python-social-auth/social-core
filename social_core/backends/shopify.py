"""
Shopify OAuth2 association backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/shopify.html
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import shopify

from social_core.backends.base import ResponseT_co
from social_core.exceptions import AuthInputError, AuthResponseError, ErrorStage
from social_core.utils import handle_http_errors

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from social_core.storage import UserProtocol


class ShopifyOAuth2(BaseOAuth2[ResponseT_co]):
    """Shopify OAuth2 association backend"""

    name = "shopify"
    title = "Shopify"
    ASSOCIATION_ONLY = True
    ID_KEY = "shop"
    EXTRA_DATA = [("shop", "shop"), ("website", "website"), ("expires", "expires")]
    REDIRECT_STATE = False
    # Shop names are a single host label, as in Shopify's own shop sanitizer
    SHOP_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

    @property
    def shopify_api_version(self):
        return self.setting("API_VERSION", "2020-10")

    def shop_session(
        self, shop: str | None, *, stage: ErrorStage, token: Any = None
    ) -> shopify.Session:
        """Return a Shopify session for a request supplied shop name

        The ShopifyAPI SDK only cuts the value at its first dot and appends
        ".myshopify.com", so any other host character survives into the
        authorization URL, where a browser may read the host differently (a
        backslash ends it, "%2e" is a dot).  Accept only names whose
        normalized label is a plain host label.
        """
        if not shop:
            raise AuthInputError(
                self, parameter="shop", code="missing_parameter", stage=stage
            )
        try:
            session = shopify.Session(
                shop.strip(), version=self.shopify_api_version, token=token
            )
        except ValueError as error:
            raise AuthInputError(
                self, parameter="shop", code="invalid_parameter", stage=stage
            ) from error
        if not self.SHOP_NAME_RE.match((session.url or "").partition(".")[0]):
            raise AuthInputError(
                self, parameter="shop", code="invalid_parameter", stage=stage
            )
        return session

    def get_user_details(self, response):
        """Use the shopify store name as the username"""
        return {"username": str(response.get("shop", "")).replace(".myshopify.com", "")}

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Return access_token and extra defined names to store in
        extra_data field"""
        data = super().extra_data(user, uid, response, details, pipeline_kwargs)
        session = self.shop_session(response.get("shop"), stage="callback")
        # Get, and store the permanent token
        try:
            token = session.request_token(data["access_token"])
        except shopify.ValidationException as error:
            raise AuthInputError(
                self, code="invalid_parameter", stage="callback"
            ) from error
        data["access_token"] = token
        return dict(data)

    def auth_url(self):
        key, secret = self.get_key_and_secret()
        shopify.Session.setup(api_key=key, secret=secret)
        scope = self.get_scope()
        state = self.get_or_create_state()
        redirect_uri = self.get_redirect_uri(state)
        session = self.shop_session(self.data.get("shop"), stage="begin")
        return session.create_permission_url(
            scope=scope, redirect_uri=redirect_uri, state=state
        )

    @handle_http_errors
    def auth_complete(self, *args, **kwargs) -> UserProtocol | ResponseT_co | None:
        """Completes login process, must return user instance"""
        self.validate_association_state(self.get_request_state(), kwargs.get("user"))
        self.process_error(self.data)
        access_token = None
        key, secret = self.get_key_and_secret()
        try:
            shop_url = self.data.get("shop")
            shopify.Session.setup(api_key=key, secret=secret)
            if not shopify.Session.validate_hmac(self.data):
                raise AuthResponseError(
                    self, code="invalid_signature", stage="callback"
                )
            shopify_session = self.shop_session(
                shop_url, stage="callback", token=self.data
            )
            access_token = shopify_session.token
        except shopify.ValidationException as error:
            raise AuthInputError(
                self, code="invalid_parameter", stage="callback"
            ) from error
        if not access_token:
            raise AuthResponseError(
                self,
                "Authentication Failed",
                code="malformed_response",
                stage="callback",
            )
        return self.do_auth(
            access_token, shop_url, shopify_session.url, *args, **kwargs
        )

    def do_auth(self, access_token, shop_url, website, *args, **kwargs):
        self._bind_association_user(kwargs)
        kwargs.update(
            {
                "backend": self,
                "response": {
                    "shop": shop_url,
                    "website": f"http://{website}",
                    "access_token": access_token,
                },
            }
        )
        return self.strategy.authenticate(*args, **kwargs)
