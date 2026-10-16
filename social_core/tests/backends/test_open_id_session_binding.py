from __future__ import annotations

import datetime as dt
from unittest.mock import patch
from urllib.parse import urlencode

import requests
import responses
from openid.message import OPENID2_NS

from social_core.backends.open_id import OpenIdAuth
from social_core.exceptions import AuthSessionError
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import User
from social_core.tests.strategy import TestStrategy
from social_core.utils import parse_qs

from .open_id import OpenIdTest


class GenericOpenIdBrowserBindingTest(OpenIdTest):
    backend_path = "social_core.backends.open_id.OpenIdAuth"
    expected_username = "mallory"
    claimed_id = "https://attacker.example/id/mallory"
    provider_endpoint = "https://attacker.example/openid"
    discovery_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>http://specs.openid.net/auth/2.0/signon</Type>
            <URI>{provider_endpoint}</URI>
        </Service>
    </XRD>
</xrds:XRDS>"""
    server_response = ""

    def openid_url(self) -> str:
        return self.claimed_id

    def get_server_response(self, inputs: dict[str, str | None]) -> str:
        return_to = inputs["openid.return_to"]
        assert return_to is not None
        unsigned_session_return_to = return_to.split("?", 1)[0]
        nonce = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return urlencode(
            {
                "openid.ns": OPENID2_NS,
                "openid.mode": "id_res",
                "openid.op_endpoint": self.provider_endpoint,
                "openid.claimed_id": self.claimed_id,
                "openid.identity": self.claimed_id,
                "openid.return_to": unsigned_session_return_to,
                "openid.response_nonce": f"{nonce}nonce",
                "openid.assoc_handle": "attacker-handle",
                "openid.signed": (
                    "signed,op_endpoint,claimed_id,identity,return_to,"
                    "response_nonce,assoc_handle"
                ),
                "openid.sig": "attacker-signature",
            }
        )

    def test_signed_response_without_session_id_cannot_use_victim_session(
        self,
    ) -> None:
        self.add_openid_response(
            "GET",
            self.claimed_id,
            body=self.discovery_body,
            content_type="application/xrds+xml",
        )
        self.strategy.set_request_data(
            {"openid_identifier": self.claimed_id}, self.backend
        )
        with patch.object(
            self.strategy, "get_session_id", return_value="attacker-session"
        ):
            start = self.backend.start()
        form, inputs = self.get_form_data(start)
        return_to = inputs["openid.return_to"]
        assert return_to is not None
        self.assertIn("psa_session_id=attacker-session", return_to)
        action = form["action"]
        assert action is not None
        responses.add(
            responses.POST,
            action,
            status=200,
            body=self.get_server_response(inputs),
        )
        provider_response = requests.post(action, data=inputs, timeout=1)

        victim_strategy = TestStrategy(self.strategy.storage)
        victim_strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": (
                    self.backend_path,
                    "social_core.tests.backends.test_broken.BrokenBackendAuth",
                )
            }
        )
        victim_backend = OpenIdAuth(
            victim_strategy,
            redirect_uri=self.complete_url,
        )
        victim_strategy.set_request_data(
            parse_qs(provider_response.content), victim_backend
        )
        self.add_openid_response(
            "POST",
            self.provider_endpoint,
            body="is_valid:true\n",
        )
        victim = User("victim")
        with (
            patch.object(victim_strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            victim_backend.complete(user=victim)
        authenticate.assert_not_called()

    def test_same_session_response_uses_saved_discovery_state(self) -> None:
        self.add_openid_response(
            "GET",
            self.claimed_id,
            body=self.discovery_body,
            content_type="application/xrds+xml",
        )
        self.strategy.set_request_data(
            {"openid_identifier": self.claimed_id}, self.backend
        )
        start = self.backend.start()
        form, inputs = self.get_form_data(start)
        action = form["action"]
        assert action is not None
        responses.add(
            responses.POST,
            action,
            status=200,
            body=self.get_server_response(inputs),
        )
        provider_response = requests.post(action, data=inputs, timeout=1)

        callback_strategy = self.strategy.new_request()
        callback_backend = OpenIdAuth(
            callback_strategy,
            redirect_uri=self.complete_url,
        )
        callback_strategy.set_request_data(
            parse_qs(provider_response.content), callback_backend
        )
        self.add_openid_response(
            "POST",
            self.provider_endpoint,
            body="is_valid:true\n",
        )
        with patch.object(
            callback_strategy, "authenticate", return_value="authenticated"
        ) as authenticate:
            self.assertEqual(callback_backend.complete(), "authenticated")
        authenticate.assert_called_once()
        self.assertEqual(callback_strategy.session_get("openid"), {})
