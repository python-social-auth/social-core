from html.parser import HTMLParser

import requests
import responses
from openid import fetchers
from openid.fetchers import HTTPResponse

from social_core.backends.utils import load_backends
from social_core.tests.models import (
    TestAssociation,
    TestNonce,
    TestStorage,
    TestUserSocialAuth,
    User,
)
from social_core.tests.strategy import TestStrategy
from social_core.utils import module_member, parse_qs

from .base import BaseBackendTest


class FormHTMLParser(HTMLParser):
    form: dict[str, str | None] = {}
    inputs: dict[str, str | None] = {}

    def handle_starttag(self, tag, attrs) -> None:
        attrs = dict(attrs)
        if tag == "form":
            self.form.update(attrs)
        elif tag == "input":
            name = attrs.get("name")
            if name is not None:
                self.inputs[name] = attrs.get("value")


class OpenIdTestFetcher(fetchers.HTTPFetcher):
    def __init__(self) -> None:
        self._responses: dict[tuple[str, str], list[HTTPResponse]] = {}

    def add_response(
        self,
        method: str,
        url: str,
        *,
        status: int = 200,
        body: str = "",
        content_type: str | None = None,
    ) -> None:
        headers = {}
        if content_type:
            headers["content-type"] = content_type
        response = HTTPResponse(
            final_url=url,
            status=status,
            headers=headers,
            body=body,
        )
        self._responses.setdefault((method, url), []).append(response)

    def fetch(self, url, body=None, headers=None):
        method = "POST" if body is not None else "GET"
        try:
            matching_responses = self._responses[(method, url)]
        except KeyError as err:
            raise AssertionError(
                f"Unexpected OpenID {method} request to {url}"
            ) from err
        if len(matching_responses) > 1:
            return matching_responses.pop(0)
        return matching_responses[0]


class OpenIdTest(BaseBackendTest):
    discovery_body: str
    server_response: str

    def setUp(self) -> None:
        responses.start()
        self.openid_fetcher = OpenIdTestFetcher()
        self._default_openid_fetcher = fetchers.getDefaultFetcher()
        fetchers.setDefaultFetcher(self.openid_fetcher)
        Backend = module_member(self.backend_path)
        self.strategy = TestStrategy(TestStorage)
        self.complete_url = self.raw_complete_url.format(Backend.name)
        self.backend = Backend(self.strategy, redirect_uri=self.complete_url)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": (
                    self.backend_path,
                    "social_core.tests.backends.test_broken.BrokenBackendAuth",
                )
            }
        )
        # Force backends loading to trash PSA cache
        load_backends(
            self.strategy.get_setting("SOCIAL_AUTH_AUTHENTICATION_BACKENDS"),
            force_load=True,
        )

    def tearDown(self) -> None:
        fetchers.setDefaultFetcher(self._default_openid_fetcher, wrap_exceptions=False)
        del self.strategy
        del self.openid_fetcher
        del self._default_openid_fetcher
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        TestNonce.reset_cache()
        TestAssociation.reset_cache()
        responses.stop()
        responses.reset()

    def get_form_data(self, html):
        parser = FormHTMLParser()
        parser.feed(html.content)
        return parser.form, parser.inputs

    def openid_url(self):
        return self.backend.openid_url()

    def post_start(self) -> None:
        pass

    def get_server_response(self, inputs: dict[str, str | None]) -> str:
        return self.server_response

    def add_openid_response(
        self,
        method: str,
        url: str,
        *,
        status: int = 200,
        body: str = "",
        content_type: str | None = None,
    ) -> None:
        self.openid_fetcher.add_response(
            method,
            url,
            status=status,
            body=body,
            content_type=content_type,
        )

    def do_start(self):
        self.add_openid_response(
            "GET",
            self.openid_url(),
            body=self.discovery_body,
            content_type="application/xrds+xml",
        )
        responses.add(
            responses.GET,
            self.openid_url(),
            status=200,
            body=self.discovery_body,
            content_type="application/xrds+xml",
        )
        start = self.backend.start()
        self.post_start()
        form, inputs = self.get_form_data(start)
        action = form.get("action")
        assert action, "The form action must be set in the test"
        responses.add(
            responses.POST,
            action,
            status=200,
            body=self.get_server_response(inputs),
        )
        response = requests.post(action, data=inputs, timeout=1)
        self.strategy.set_request_data(parse_qs(response.content), self.backend)
        self.add_openid_response(
            "POST",
            action,
            body="is_valid:true\n",
        )
        responses.add(
            responses.POST,
            form.get("action"),
            status=200,
            body="is_valid:true\n",
        )
        return self.backend.complete()
