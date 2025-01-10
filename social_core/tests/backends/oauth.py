# pyright: reportAttributeAccessIssue=false

from unittest.mock import patch
from urllib.parse import urlparse

import requests
from httpretty import HTTPretty, latest_requests

from ...utils import parse_qs, url_add_parameters
from ..models import User
from .base import BaseBackendTest


class BaseOAuthTest(BaseBackendTest):
    backend = None
    backend_path = None
    user_data_body = None
    user_data_url = ""
    user_data_url_post = False
    user_data_content_type = "application/json"
    access_token_body = None
    access_token_status = 200
    expected_username = ""

    def extra_settings(self):
        assert self.name, "Subclasses must set the name attribute"
        return {
            "SOCIAL_AUTH_" + self.name + "_KEY": "a-key",
            "SOCIAL_AUTH_" + self.name + "_SECRET": "a-secret-key",
        }

    def _method(self, method):
        return {"GET": HTTPretty.GET, "POST": HTTPretty.POST}[method]

    def handle_state(self, start_url, target_url):
        start_query = parse_qs(urlparse(start_url).query)
        redirect_uri = start_query.get("redirect_uri")

        if getattr(self.backend, "STATE_PARAMETER", False) and start_query.get("state"):
            target_url = url_add_parameters(target_url, {"state": start_query["state"]})

        if redirect_uri and getattr(self.backend, "REDIRECT_STATE", False):
            redirect_query = parse_qs(urlparse(redirect_uri).query)
            if redirect_query.get("redirect_state"):
                target_url = url_add_parameters(
                    target_url, {"redirect_state": redirect_query["redirect_state"]}
                )
        return target_url

    def auth_handlers(self, start_url):
        target_url = self.handle_state(
            start_url, self.strategy.build_absolute_uri(self.complete_url)
        )
        HTTPretty.register_uri(
            HTTPretty.GET, start_url, status=301, location=target_url
        )
        HTTPretty.register_uri(HTTPretty.GET, target_url, status=200, body="foobar")
        if self.user_data_url:
            HTTPretty.register_uri(
                HTTPretty.POST if self.user_data_url_post else HTTPretty.GET,
                self.user_data_url,
                body=self.user_data_body or "",
                content_type=self.user_data_content_type,
            )
        return target_url

    def pre_complete_callback(self, start_url):
        HTTPretty.register_uri(
            self._method(self.backend.ACCESS_TOKEN_METHOD),
            uri=self.backend.access_token_url(),
            status=self.access_token_status,
            body=self.access_token_body or "",
            content_type="text/json",
        )

    def do_start(self):
        start_url = self.backend.start().url
        target_url = self.auth_handlers(start_url)
        response = requests.get(start_url)
        self.assertEqual(response.url, target_url)
        self.assertEqual(response.text, "foobar")
        self.strategy.set_request_data(
            parse_qs(urlparse(start_url).query), self.backend
        )
        self.strategy.set_request_data(
            parse_qs(urlparse(target_url).query), self.backend
        )
        self.pre_complete_callback(start_url)
        return self.backend.complete()


class OAuth1Test(BaseOAuthTest):
    request_token_body = None
    raw_complete_url = "/complete/{0}/?oauth_verifier=bazqux&oauth_token=foobar"

    def request_token_handler(self):
        assert self.request_token_body, "Subclasses must set request_token_body"
        HTTPretty.register_uri(
            self._method(self.backend.REQUEST_TOKEN_METHOD),
            self.backend.REQUEST_TOKEN_URL,
            body=self.request_token_body,
            status=200,
        )

    def do_start(self):
        self.request_token_handler()
        return super().do_start()


class OAuth2Test(BaseOAuthTest):
    raw_complete_url = "/complete/{0}/?code=foobar"
    refresh_token_body = ""

    def refresh_token_arguments(self):
        return {}

    def do_refresh_token(self):
        self.do_login()
        HTTPretty.register_uri(
            self._method(self.backend.REFRESH_TOKEN_METHOD),
            self.backend.refresh_token_url(),
            status=200,
            body=self.refresh_token_body,
        )
        user = next(iter(User.cache.values()))
        social = user.social[0]
        social.refresh_token(strategy=self.strategy, **self.refresh_token_arguments())
        return user, social


class OAuth2PkcePlainTest(OAuth2Test):
    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {f"SOCIAL_AUTH_{self.name}_PKCE_CODE_CHALLENGE_METHOD": "plain"}
        )
        return settings

    def do_login(self):
        user = super().do_login()

        requests = latest_requests()
        auth_request = next(
            r for r in requests if self.backend.authorization_url() in r.url
        )
        code_challenge = auth_request.querystring.get("code_challenge")[0]
        code_challenge_method = auth_request.querystring.get("code_challenge_method")[0]
        self.assertIsNotNone(code_challenge)
        self.assertEqual(code_challenge_method, "plain")

        auth_complete = next(
            r for r in requests if self.backend.access_token_url() in r.url
        )
        code_verifier = auth_complete.parsed_body.get("code_verifier")[0]
        self.assertEqual(code_challenge, code_verifier)

        return user


class OAuth2PkceS256Test(OAuth2Test):
    def do_login(self):
        # use default value of PKCE_CODE_CHALLENGE_METHOD (s256)
        user = super().do_login()

        requests = latest_requests()
        auth_request = next(
            r for r in requests if self.backend.authorization_url() in r.url
        )
        code_challenge = auth_request.querystring.get("code_challenge")[0]
        code_challenge_method = auth_request.querystring.get("code_challenge_method")[0]
        self.assertIsNotNone(code_challenge)
        self.assertTrue(code_challenge_method in ["s256", "S256"])

        auth_complete = next(
            r for r in requests if self.backend.access_token_url() in r.url
        )
        code_verifier = auth_complete.parsed_body.get("code_verifier")[0]
        self.assertEqual(
            self.backend.generate_code_challenge(code_verifier, code_challenge_method),
            code_challenge,
        )

        return user


class BaseAuthUrlTestMixin:
    def check_parameters_in_authorization_url(self, auth_url_key="AUTHORIZATION_URL"):
        """
        Check the parameters in authorization url

        When inserting parameters directly into AUTHORIZATION_URL, we expect the
        other parameters to be added to the end of the url
        """
        original_url = (
            self.backend.AUTHORIZATION_URL or self.backend.authorization_url()
        )
        with (
            patch.object(
                self.backend,
                "authorization_url",
                return_value=original_url + "?param1=value1&param2=value2",
            ),
            patch.object(
                self.backend,
                auth_url_key,
                original_url + "?param1=value1&param2=value2",
            ),
        ):
            # we expect an & symbol to join the different parameters
            assert "?param1=value1&param2=value2&" in self.backend.auth_url()

    def test_auth_url_parameters(self):
        self.check_parameters_in_authorization_url()


class OAuth1AuthUrlTestMixin(BaseAuthUrlTestMixin):
    def test_auth_url_parameters(self):
        self.request_token_handler()
        self.check_parameters_in_authorization_url()
