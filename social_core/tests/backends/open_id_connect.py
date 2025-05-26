from __future__ import annotations

import base64
import datetime
import json
from calendar import timegm
from typing import Generic, TypeVar
from urllib.parse import urlparse

import jwt
import responses

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthTokenError
from social_core.utils import parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

JWK_KEY = {
    "kty": "RSA",
    "d": "ZmswNokEvBcxW_Kvcy8mWUQOQCBdGbnM0xR7nhvGHC-Q24z3XAQWlMWbsmGc_R1o"
    "_F3zK7DBlc3BokdRaO1KJirNmnHCw5TlnBlJrXiWpFBtVglUg98-4sRRO0VWnGXK"
    "JPOkBQ6b_DYRO3b0o8CSpWowpiV6HB71cjXTqKPZf-aXU9WjCCAtxVjfIxgQFu5I"
    "-G1Qah8mZeY8HK_y99L4f0siZcbUoaIcfeWBhxi14ODyuSAHt0sNEkhiIVBZE7QZ"
    "m-SEP1ryT9VAaljbwHHPmg7NC26vtLZhvaBGbTTJnEH0ZubbN2PMzsfeNyoCIHy4"
    "4QDSpQDCHfgcGOlHY_t5gQ",
    "e": "AQAB",
    "use": "sig",
    "kid": "testkey",
    "alg": "RS256",
    "n": "pUfcJ8WFrVue98Ygzb6KEQXHBzi8HavCu8VENB2As943--bHPcQ-nScXnrRFAUg8"
    "H5ZltuOcHWvsGw_AQifSLmOCSWJAPkdNb0w0QzY7Re8NrPjCsP58Tytp5LicF0Ao"
    "Ag28UK3JioY9hXHGvdZsWR1Rp3I-Z3nRBP6HyO18pEgcZ91c9aAzsqu80An9X4DA"
    "b1lExtZorvcd5yTBzZgr-MUeytVRni2lDNEpa6OFuopHXmg27Hn3oWAaQlbymd4g"
    "ifc01oahcwl3ze2tMK6gJxa_TdCf1y99Yq6oilmVvZJ8kwWWnbPE-oDmOVPVnEyT"
    "vYVCvN4rBT1DQ-x0F1mo2Q",
}

JWK_PUBLIC_KEY = {key: value for key, value in JWK_KEY.items() if key != "d"}
OpenIdConnectAuthT = TypeVar("OpenIdConnectAuthT", bound=OpenIdConnectAuth)


class OpenIdConnectTest(
    OAuth2Test[OpenIdConnectAuthT], BaseAuthUrlTestMixin, Generic[OpenIdConnectAuthT]
):
    """
    Mixin to test OpenID Connect consumers. Inheriting classes should also
    inherit OAuth2Test.
    """

    client_key = "a-key"
    client_secret = "a-secret-key"
    issuer: str  # id_token issuer
    openid_config_body: str
    key: dict[str, str]

    # Avoid sharing access_token_kwargs between different subclasses
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.access_token_kwargs = getattr(cls, "access_token_kwargs", {})

    def setUp(self) -> None:
        if self.__class__.__name__ == "OpenIdConnectTest":
            self.skipTest("base class")
        super().setUp()
        self.key = JWK_KEY.copy()
        self.public_key = JWK_PUBLIC_KEY.copy()

        assert self.openid_config_body, "openid_config_body must be set"

        responses.add(
            responses.GET,
            self.backend.oidc_endpoint() + "/.well-known/openid-configuration",
            status=200,
            body=self.openid_config_body,
        )
        oidc_config = json.loads(self.openid_config_body)

        def jwks(_request, _uri, headers):
            return 200, headers, json.dumps({"keys": [self.key]})

        responses.add(
            responses.GET,
            oidc_config.get("jwks_uri"),
            status=200,
            body=json.dumps({"keys": [self.public_key]}),
        )

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                f"SOCIAL_AUTH_{self.name}_KEY": self.client_key,
                f"SOCIAL_AUTH_{self.name}_SECRET": self.client_secret,
                f"SOCIAL_AUTH_{self.name}_ID_TOKEN_DECRYPTION_KEY": self.client_secret,
            }
        )
        return settings

    def get_id_token(
        self,
        client_key=None,
        expiration_datetime=None,
        issue_datetime=None,
        nonce=None,
        issuer=None,
    ):
        """
        Return the id_token to be added to the access token body.
        """
        return {
            "iss": issuer,
            "nonce": nonce,
            "aud": client_key,
            "azp": client_key,
            "exp": expiration_datetime,
            "iat": issue_datetime,
            "sub": "1234",
        }

    def prepare_access_token_body(
        self,
        client_key=None,
        tamper_message=False,
        expiration_datetime=None,
        kid=None,
        issue_datetime=None,
        nonce=None,
        issuer=None,
    ):
        """
        Prepares a provider access token response. Arguments:

        client_id       -- (str) OAuth ID for the client that requested
                                 authentication.
        expiration_time -- (datetime) Date and time after which the response
                                      should be considered invalid.
        """

        body = {"access_token": "foobar", "token_type": "bearer"}
        client_key = client_key or self.client_key
        now = datetime.datetime.now(datetime.timezone.utc)
        expiration_datetime = expiration_datetime or (
            now + datetime.timedelta(seconds=30)
        )
        issue_datetime = issue_datetime or now
        nonce = nonce or "a-nonce"
        issuer = issuer or self.issuer
        id_token = self.get_id_token(
            client_key,
            timegm(expiration_datetime.timetuple()),
            timegm(issue_datetime.timetuple()),
            nonce,
            issuer,
        )
        # calc at_hash
        id_token["at_hash"] = OpenIdConnectAuth.calc_at_hash("foobar", "RS256")

        body["id_token"] = jwt.encode(
            id_token,
            key=jwt.PyJWK(
                dict(self.key, iat=timegm(issue_datetime.timetuple()), nonce=nonce)
            ).key,
            algorithm="RS256",
            headers={"kid": kid} if kid else None,
        )

        if tamper_message:
            header, msg, sig = body["id_token"].split(".")
            id_token["sub"] = "1235"
            msg = base64.encodebytes(json.dumps(id_token).encode()).decode()
            body["id_token"] = f"{header}.{msg}.{sig}"

        return json.dumps(body)

    def authtoken_raised(self, expected_message, **access_token_kwargs) -> None:
        self.access_token_kwargs = access_token_kwargs
        with self.assertRaisesRegex(AuthTokenError, expected_message):
            self.do_login()

    def pre_complete_callback(self, start_url) -> None:
        nonce = parse_qs(urlparse(start_url).query)["nonce"]

        self.access_token_kwargs.setdefault("nonce", nonce)
        self.access_token_body = self.prepare_access_token_body(
            **self.access_token_kwargs
        )
        super().pre_complete_callback(start_url)

    def test_invalid_signature(self) -> None:
        self.authtoken_raised(
            "Token error: Signature verification failed", tamper_message=True
        )

    def test_expired_signature(self) -> None:
        expiration_datetime = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(seconds=30)
        self.authtoken_raised(
            "Token error: Signature has expired",
            expiration_datetime=expiration_datetime,
        )

    def test_invalid_issuer(self) -> None:
        self.authtoken_raised("Token error: Invalid issuer", issuer="someone-else")

    def test_invalid_audience(self) -> None:
        self.authtoken_raised(
            "Token error: Invalid audience", client_key="someone-else"
        )

    def test_invalid_issue_time(self) -> None:
        expiration_datetime = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(seconds=self.backend.ID_TOKEN_MAX_AGE * 2)
        self.authtoken_raised(
            "Token error: Incorrect id_token: iat", issue_datetime=expiration_datetime
        )

    def test_invalid_nonce(self) -> None:
        self.authtoken_raised(
            "Token error: Incorrect id_token: nonce",
            nonce="something-wrong",
            kid="testkey",
        )

    def test_invalid_kid(self) -> None:
        self.authtoken_raised(
            "Token error: Signature verification failed", kid="doesnotexist"
        )
