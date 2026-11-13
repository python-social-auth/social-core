from __future__ import annotations

import urllib.parse

import responses

from social_core.tests.strategy import TEST_URI

from .base import BaseBackendTest

VALIDATION_PAYLOAD = b"""
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>test</cas:user>
    <cas:attributes>
      <cas:authenticationDate>1970-01-01T00:00:00+00:00</cas:authenticationDate>
      <cas:longTermAuthenticationRequestTokenUsed>false</cas:longTermAuthenticationRequestTokenUsed>
      <cas:isFromNewLogin>true</cas:isFromNewLogin>
      <cas:email>test@example.com</cas:email>
      <cas:name>Firstname Lastname</cas:name>
    </cas:attributes>
    <cas:attribute name="authenticationDate" value="1970-00-00T00:00:00+00:00"/>
    <cas:attribute name="longTermAuthenticationRequestTokenUsed" value="false"/>
    <cas:attribute name="isFromNewLogin" value="true"/>
    <cas:attribute name="email" value="test@example.com"/>
    <cas:attribute name="name" value="Firstname Lastname"/>
  </cas:authenticationSuccess>
</cas:serviceResponse>
"""


class CasAuthTest(BaseBackendTest):
    backend_path = "social_core.backends.cas_generic.CasAuth"
    expected_username = "test"
    ticket = "ST-12345678"
    server_url = "http://cas-server.com/"
    service_url = TEST_URI
    validate_endpoint = "p3/serviceValidate"

    def setUp(self) -> None:
        super().setUp()
        params = [("ticket", self.ticket), ("service", self.service_url)]

        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_CAS_SERVER_URL": self.server_url,
            }
        )

        url = (
            urllib.parse.urljoin(self.server_url, self.validate_endpoint)
            + "?"
            + urllib.parse.urlencode(params)
        )
        responses.add(responses.GET, url, VALIDATION_PAYLOAD)

    def do_start(self):
        self.strategy.set_request_data({"ticket": self.ticket}, self.backend)
        return self.backend.complete()

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_auth_url(self) -> None:
        self.assertEqual(
            self.backend.auth_url(),
            urllib.parse.urljoin(self.server_url, "login")
            + "?"
            + urllib.parse.urlencode({"service": self.service_url}),
        )
