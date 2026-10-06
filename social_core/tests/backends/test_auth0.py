import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import jwt
import requests
import responses
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from social_core.exceptions import AuthProviderError, AuthResponseError
from social_core.tests.exception_helpers import assert_auth_error
from social_core.utils import get_querystring

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

if TYPE_CHECKING:
    from typing import Any

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
    "kid": "foobar",
    "alg": "RS256",
    "n": "pUfcJ8WFrVue98Ygzb6KEQXHBzi8HavCu8VENB2As943--bHPcQ-nScXnrRFAUg8"
    "H5ZltuOcHWvsGw_AQifSLmOCSWJAPkdNb0w0QzY7Re8NrPjCsP58Tytp5LicF0Ao"
    "Ag28UK3JioY9hXHGvdZsWR1Rp3I-Z3nRBP6HyO18pEgcZ91c9aAzsqu80An9X4DA"
    "b1lExtZorvcd5yTBzZgr-MUeytVRni2lDNEpa6OFuopHXmg27Hn3oWAaQlbymd4g"
    "ifc01oahcwl3ze2tMK6gJxa_TdCf1y99Yq6oilmVvZJ8kwWWnbPE-oDmOVPVnEyT"
    "vYVCvN4rBT1DQ-x0F1mo2Q",
}

JWK_PUBLIC_KEY = {key: value for key, value in JWK_KEY.items() if key != "d"}

DOMAIN = "foobar.auth0.com"


class Auth0OAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.auth0.Auth0OAuth2"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "expires_in": 86400,
            "id_token": jwt.encode(
                {
                    "nickname": "foobar",
                    "email": "foobar@auth0.com",
                    "name": "John Doe",
                    "picture": "http://example.com/image.png",
                    "sub": "123456",
                    "iss": f"https://{DOMAIN}/",
                    "aud": "a-key",
                },
                jwt.PyJWK(JWK_KEY).key,
                algorithm="RS256",
            ),
        }
    )
    expected_username = "foobar"
    jwks_url = "https://foobar.auth0.com/.well-known/jwks.json"

    def setUp(self) -> None:
        super().setUp()
        cached_keys: Any = self.backend.get_jwks_keys_for_uri
        cached_keys.invalidate()
        self.addCleanup(cached_keys.invalidate)

    def extra_settings(self):
        assert self.name, "Subclasses must set the name attribute"
        settings = super().extra_settings()
        settings[f"SOCIAL_AUTH_{self.name}_DOMAIN"] = DOMAIN
        return settings

    def auth_handlers(self, start_url):
        responses.add(
            responses.GET,
            self.jwks_url,
            body=json.dumps({"keys": [JWK_PUBLIC_KEY]}),
            content_type="application/json",
        )
        return super().auth_handlers(start_url)

    def test_login(self) -> None:
        self.do_login()

    def token_response(self) -> dict:
        assert self.access_token_body is not None
        return json.loads(self.access_token_body)

    def test_non_object_jwks_rejected_before_caching(self) -> None:
        cached_keys: Any = self.backend.get_jwks_keys_for_uri
        for payload in (None, [], [JWK_PUBLIC_KEY], "keys", 1, False):
            cached_keys.invalidate()
            with (
                self.subTest(payload=payload),
                patch.object(
                    self.backend,
                    "get_json",
                    side_effect=[payload, {"keys": [JWK_PUBLIC_KEY]}],
                ) as get_json,
            ):
                with assert_auth_error(
                    self, AuthResponseError, "malformed_response"
                ) as caught:
                    self.backend.get_user_details(self.token_response())
                self.assertEqual(caught.exception.stage, "token_validation")
                self.assertEqual(caught.exception.source, "provider_response")
                self.assertEqual(
                    self.backend.get_user_details(self.token_response())["user_id"],
                    "123456",
                )
                self.backend.get_user_details(self.token_response())
                self.assertEqual(get_json.call_count, 2)
                get_json.assert_called_with(self.jwks_url, stage="token_validation")

    def test_signed_token_allows_omitted_optional_profile_claims(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        response = self.token_response()
        claims = jwt.decode(response["id_token"], options={"verify_signature": False})
        for claim in ("name", "nickname", "email", "picture"):
            del claims[claim]
        response["id_token"] = jwt.encode(
            claims, jwt.PyJWK(JWK_KEY).key, algorithm="RS256"
        )
        details = self.backend.get_user_details(response)
        self.assertEqual(details["user_id"], "123456")
        for field in ("fullname", "first_name", "last_name"):
            self.assertIsNone(details[field])
        for field in ("username", "email", "picture"):
            self.assertEqual(details[field], "")

    def test_signed_token_requires_subject(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        response = self.token_response()
        claims = jwt.decode(response["id_token"], options={"verify_signature": False})
        del claims["sub"]
        response["id_token"] = jwt.encode(
            claims, jwt.PyJWK(JWK_KEY).key, algorithm="RS256"
        )
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.get_user_details(response)
        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertEqual(caught.exception.claim, "sub")
        self.assertEqual(caught.exception.stage, "token_validation")

    def test_jwks_cache_shared_between_validations_and_instances(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()
        other_backend = self.backend.__class__(self.strategy)

        details = self.backend.get_user_details(token)
        self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(other_backend.get_user_details(token), details)

        self.assertEqual(len(responses.calls), 1)

    def test_jwks_cache_isolated_by_domain(self) -> None:
        other_domain = "other.auth0.com"
        other_url = f"https://{other_domain}/.well-known/jwks.json"
        other_key = {**JWK_PUBLIC_KEY, "kid": "other-key"}
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        responses.add(responses.GET, other_url, json={"keys": [other_key]})

        keys = self.backend.get_jwks_keys_for_uri(
            self.backend.api_path(".well-known/jwks.json")
        )
        self.strategy.set_settings({"SOCIAL_AUTH_AUTH0_DOMAIN": other_domain})
        other_keys = self.backend.get_jwks_keys_for_uri(
            self.backend.api_path(".well-known/jwks.json")
        )
        self.strategy.set_settings({"SOCIAL_AUTH_AUTH0_DOMAIN": DOMAIN})
        cached_keys = self.backend.get_jwks_keys_for_uri(
            self.backend.api_path(".well-known/jwks.json")
        )

        self.assertEqual(keys[0].key_id, "foobar")
        self.assertEqual(other_keys[0].key_id, "other-key")
        self.assertEqual(cached_keys[0].key_id, "foobar")
        self.assertEqual(
            [call.request.url for call in responses.calls], [self.jwks_url, other_url]
        )

    def test_jwks_cache_expires_after_24_hours(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()

        with patch("social_core.utils.time.time", return_value=1000):
            details = self.backend.get_user_details(token)
        with patch("social_core.utils.time.time", return_value=1000 + 86400):
            self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(len(responses.calls), 1)
        with patch("social_core.utils.time.time", return_value=1000 + 86401):
            self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(len(responses.calls), 2)

    def test_expired_jwks_cache_retains_keys_when_fetch_fails(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()

        with patch("social_core.utils.time.time", return_value=1000):
            details = self.backend.get_user_details(token)
        responses.replace(
            responses.GET, self.jwks_url, body=requests.ReadTimeout("timed out")
        )
        with patch("social_core.utils.time.time", return_value=1000 + 86401):
            self.assertEqual(self.backend.get_user_details(token), details)

        self.assertEqual(len(responses.calls), 2)

    def test_invalid_jwk_is_not_cached(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={})
        token = self.token_response()

        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.backend.get_user_details(token)
        responses.replace(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        self.assertEqual(self.backend.get_user_details(token)["user_id"], "123456")
        self.assertEqual(len(responses.calls), 2)

    def test_unknown_kid_refreshes_jwks_for_rotated_key(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()
        details = self.backend.get_user_details(token)
        rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rotated_jwk = RSAAlgorithm.to_jwk(rotated_key.public_key(), as_dict=True)
        rotated_jwk["kid"] = "rotated-key"
        responses.replace(responses.GET, self.jwks_url, json={"keys": [rotated_jwk]})
        claims = jwt.decode(token["id_token"], options={"verify_signature": False})
        token["id_token"] = jwt.encode(
            claims, rotated_key, algorithm="RS256", headers={"kid": "rotated-key"}
        )

        self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(len(responses.calls), 2)

    def test_rotation_without_kid_refreshes_once(self) -> None:
        for single_jwk in (False, True):
            with self.subTest(single_jwk=single_jwk):
                responses.reset()
                cached_keys: Any = self.backend.get_jwks_keys_for_uri
                cached_keys.invalidate()
                responses.add(
                    responses.GET,
                    self.jwks_url,
                    json=JWK_PUBLIC_KEY if single_jwk else {"keys": [JWK_PUBLIC_KEY]},
                )
                token = self.token_response()
                details = self.backend.get_user_details(token)
                rotated_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048
                )
                rotated_jwk = RSAAlgorithm.to_jwk(
                    rotated_key.public_key(), as_dict=True
                )
                responses.replace(
                    responses.GET,
                    self.jwks_url,
                    json=rotated_jwk if single_jwk else {"keys": [rotated_jwk]},
                )
                claims = jwt.decode(
                    token["id_token"], options={"verify_signature": False}
                )
                token["id_token"] = jwt.encode(claims, rotated_key, algorithm="RS256")

                self.assertEqual(self.backend.get_user_details(token), details)
                self.assertEqual(self.backend.get_user_details(token), details)
                self.assertEqual(len(responses.calls), 2)

    def test_rotation_preserves_other_domains_cached_keys(self) -> None:
        other_url = "https://other.auth0.com/.well-known/jwks.json"
        responses.add(responses.GET, other_url, json={"keys": [JWK_PUBLIC_KEY]})
        other_keys = self.backend.get_jwks_keys_for_uri(other_url)
        responses.replace(
            responses.GET, other_url, body=requests.ReadTimeout("timed out")
        )

        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()
        details = self.backend.get_user_details(token)
        rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rotated_jwk = RSAAlgorithm.to_jwk(rotated_key.public_key(), as_dict=True)
        rotated_jwk["kid"] = "rotated-key"
        responses.replace(responses.GET, self.jwks_url, json={"keys": [rotated_jwk]})
        claims = jwt.decode(token["id_token"], options={"verify_signature": False})
        token["id_token"] = jwt.encode(
            claims, rotated_key, algorithm="RS256", headers={"kid": "rotated-key"}
        )
        self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(len(responses.calls), 3)

        self.assertIs(self.backend.get_jwks_keys_for_uri(other_url), other_keys)
        self.assertEqual(
            sum(call.request.url == other_url for call in responses.calls), 1
        )
        with patch("social_core.utils.time.time", return_value=10**12):
            self.assertIs(self.backend.get_jwks_keys_for_uri(other_url), other_keys)

    def test_failed_rotation_refresh_preserves_cached_keys(self) -> None:
        rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rotated_jwk = RSAAlgorithm.to_jwk(rotated_key.public_key(), as_dict=True)
        rotated_jwk["kid"] = "rotated-key"
        for kid in (None, "rotated-key"):
            for failure in ("timeout", "invalid-jwk"):
                with self.subTest(kid=kid, failure=failure):
                    responses.reset()
                    cached_keys: Any = self.backend.get_jwks_keys_for_uri
                    cached_keys.invalidate()
                    responses.add(
                        responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]}
                    )
                    token = self.token_response()
                    details = self.backend.get_user_details(token)
                    claims = jwt.decode(
                        token["id_token"], options={"verify_signature": False}
                    )
                    rotated_token = {
                        "id_token": jwt.encode(
                            claims,
                            rotated_key,
                            algorithm="RS256",
                            headers={} if kid is None else {"kid": kid},
                        )
                    }
                    if failure == "timeout":
                        responses.replace(
                            responses.GET,
                            self.jwks_url,
                            body=requests.ReadTimeout("timed out"),
                        )
                        expected_error: type[Exception] = AuthProviderError
                        expected_code = "timeout"
                    else:
                        responses.replace(responses.GET, self.jwks_url, json={})
                        expected_error = AuthResponseError
                        expected_code = "invalid_claim"

                    with assert_auth_error(self, expected_error, expected_code):
                        self.backend.get_user_details(rotated_token)

                    self.assertEqual(self.backend.get_user_details(token), details)
                    self.assertEqual(len(responses.calls), 2)
                    responses.replace(
                        responses.GET, self.jwks_url, json={"keys": [rotated_jwk]}
                    )
                    self.assertEqual(
                        self.backend.get_user_details(rotated_token), details
                    )
                    self.assertEqual(
                        self.backend.get_user_details(rotated_token), details
                    )
                    self.assertEqual(len(responses.calls), 3)

    def test_invalid_claim_does_not_refresh_cached_keys(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()
        self.backend.get_user_details(token)
        claims = jwt.decode(token["id_token"], options={"verify_signature": False})
        claims["aud"] = "wrong-audience"
        token["id_token"] = jwt.encode(
            claims, jwt.PyJWK(JWK_KEY).key, algorithm="RS256"
        )

        with assert_auth_error(self, AuthResponseError, "invalid_claim") as context:
            self.backend.get_user_details(token)

        self.assertIsInstance(context.exception.__cause__, jwt.InvalidAudienceError)
        self.assertEqual(len(responses.calls), 1)

    def test_invalid_signature_without_kid_refreshes_only_once(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()
        self.backend.get_user_details(token)
        header, payload, _signature = token["id_token"].split(".")
        token["id_token"] = f"{header}.{payload}.AAAA"

        with assert_auth_error(self, AuthResponseError, "invalid_signature") as context:
            self.backend.get_user_details(token)

        self.assertIsInstance(context.exception.__cause__, jwt.InvalidSignatureError)
        self.assertEqual(len(responses.calls), 2)

    def test_unknown_kid_refreshes_only_once_and_rejects_invalid_token(self) -> None:
        responses.add(responses.GET, self.jwks_url, json={"keys": [JWK_PUBLIC_KEY]})
        token = self.token_response()
        self.backend.get_user_details(token)
        claims = jwt.decode(token["id_token"], options={"verify_signature": False})
        unknown_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token["id_token"] = jwt.encode(
            claims, unknown_key, algorithm="RS256", headers={"kid": "unknown-key"}
        )

        with assert_auth_error(self, AuthResponseError, "invalid_signature"):
            self.backend.get_user_details(token)

        self.assertEqual(len(responses.calls), 2)

    def test_single_jwk_is_cached_for_token_without_kid(self) -> None:
        responses.add(responses.GET, self.jwks_url, json=JWK_PUBLIC_KEY)
        token = self.token_response()
        self.assertNotIn("kid", jwt.get_unverified_header(token["id_token"]))

        details = self.backend.get_user_details(token)
        self.assertEqual(self.backend.get_user_details(token), details)
        self.assertEqual(len(responses.calls), 1)

    def test_login_with_configured_token_claim_id(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_AUTH0_ID_KEY": "sub"})

        user = self.do_login()

        self.assertEqual(user.social[0].uid, "123456")

    def test_missing_configured_token_claim_raises_token_error(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_AUTH0_ID_KEY": "missing_claim"})

        with assert_auth_error(self, AuthResponseError, "missing_claim"):
            self.do_login()

    def test_default_scope(self) -> None:
        self.assertEqual(
            get_querystring(self.backend.auth_url())["scope"],
            "openid profile email",
        )

    def test_custom_scope_is_combined_with_default_scope(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_AUTH0_SCOPE": ["custom"]})

        self.assertEqual(
            get_querystring(self.backend.auth_url())["scope"],
            "custom openid profile email",
        )

    def test_missing_id_token_raises_auth_token_error(self) -> None:
        with (
            patch.object(self.backend, "get_json") as get_json,
            assert_auth_error(self, AuthResponseError, "missing_claim") as caught,
        ):
            self.backend.get_user_details({})

        get_json.assert_not_called()
        self.assertEqual(caught.exception.claim, "id_token")
        self.assertEqual(caught.exception.stage, "token_validation")

    def test_invalid_signature_raises_auth_token_error(self) -> None:
        assert self.access_token_body is not None
        id_token = json.loads(self.access_token_body)["id_token"]
        header, payload, _signature = id_token.split(".")

        with (
            patch.object(
                self.backend, "get_json", return_value={"keys": [JWK_PUBLIC_KEY]}
            ),
            self.assertRaises(AuthResponseError) as context,
        ):
            self.backend.get_user_details({"id_token": f"{header}.{payload}.AAAA"})

        self.assertIsInstance(context.exception.__cause__, jwt.InvalidSignatureError)

    def test_invalid_jwk_raises_auth_token_error(self) -> None:
        assert self.access_token_body is not None
        id_token = json.loads(self.access_token_body)["id_token"]

        with (
            patch.object(self.backend, "get_json", return_value={}),
            self.assertRaises(AuthResponseError) as context,
        ):
            self.backend.get_user_details({"id_token": id_token})

        self.assertIsInstance(context.exception.__cause__, jwt.PyJWTError)

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
