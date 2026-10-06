from __future__ import annotations

import base64
import datetime
from calendar import timegm
from json import loads
from typing import TYPE_CHECKING, Any, Literal, cast

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidTokenError,
    PyJWTError,
)
from jwt.utils import base64url_decode

from social_core.backends.oauth import BaseOAuth2PKCE
from social_core.backends.utils import jwt_error, load_oidc_config
from social_core.exceptions import (
    AuthConfigurationError,
    AuthCredentialError,
    AuthResponseError,
    ErrorStage,
    SocialAuthBaseException,
)
from social_core.groups import check_group_overage, configured_group_key, read_groups
from social_core.utils import cache, constant_time_compare

_ID_TOKEN_CONTEXT_KEY = "_oidc_id_token_context"
_VALIDATED_ID_TOKEN_KEY = "_oidc_validated_id_token"

if TYPE_CHECKING:
    from collections.abc import Mapping

    from jwt.types import Options
    from requests.auth import AuthBase

    from social_core.storage import PartialMixin, UserProtocol
    from social_core.strategy import BaseStrategy, HttpResponseProtocol


class OpenIdConnectAssociation:
    """Use Association model to save the nonce by force."""

    def __init__(self, handle, secret="", issued=0, lifetime=0, assoc_type="") -> None:
        self.handle = handle  # as nonce
        self.secret = secret.encode()  # not use
        self.issued = issued  # not use
        self.lifetime = lifetime  # not use
        self.assoc_type = assoc_type  # as state


class OpenIdConnectAuth(BaseOAuth2PKCE):
    """
    Base class for Open ID Connect backends.
    Currently only the code response type is supported.

    It can also be directly instantiated as a generic OIDC backend.
    To use it you will need to set at minimum:

    SOCIAL_AUTH_OIDC_OIDC_ENDPOINT = 'https://.....'  # endpoint without /.well-known/openid-configuration
    SOCIAL_AUTH_OIDC_KEY = '<client_id>'
    SOCIAL_AUTH_OIDC_SECRET = '<client_secret>'
    SOCIAL_AUTH_OIDC_USE_PKCE = True  # optional, enables PKCE for this backend
    """

    name = "oidc"
    title = "OpenID Connect"
    # Override OIDC_ENDPOINT in your subclass to enable autoconfig of OIDC
    OIDC_ENDPOINT: str | None = None
    ID_TOKEN_MAX_AGE = 600
    DEFAULT_SCOPE = ["openid", "profile", "email"]
    EXTRA_DATA = ["id_token", "refresh_token", ("sub", "id")]
    REDIRECT_STATE = False
    REVOKE_TOKEN_METHOD: Literal["GET", "POST", "DELETE"] = "GET"
    ID_KEY = "sub"
    USERNAME_KEY = "preferred_username"
    EMAIL_KEY = "email"
    FIRST_NAME_KEY = "given_name"
    LAST_NAME_KEY = "family_name"
    FULLNAME_KEY = "name"
    JWT_ALGORITHMS = ["RS256"]
    JWT_DECODE_OPTIONS: Options = {}
    JWT_LEEWAY: float = 1.0  # seconds
    VALIDATE_AT_HASH: bool = True
    CUSTOM_AT_HASH_ALGO: str | None = None
    # When these options are unspecified, server will choose via openid autoconfiguration
    ID_TOKEN_ISSUER = ""
    ACCESS_TOKEN_URL = ""
    AUTHORIZATION_URL = ""
    REVOKE_TOKEN_URL = ""
    USERINFO_URL = ""
    JWKS_URI = ""
    TOKEN_ENDPOINT_AUTH_METHOD = ""
    # Optional parameters for Authentication Request
    DISPLAY: str | None = None
    PROMPT: str | None = None
    MAX_AGE: int | None = None
    UI_LOCALES: str | None = None
    ID_TOKEN_HINT: str | None = None
    LOGIN_HINT: str | None = None
    ACR_VALUES: str | None = None
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    DEFAULT_USE_PKCE = False

    def __init__(
        self, strategy: BaseStrategy | None = None, redirect_uri: str | None = None
    ) -> None:
        super().__init__(strategy, redirect_uri=redirect_uri)
        self.id_token: dict[str, Any] | None = None

    def pipeline(
        self, pipeline, pipeline_index: int = 0, *args, **kwargs
    ) -> UserProtocol | HttpResponseProtocol | None:
        # Only persist claims validated by this backend, never caller-supplied
        # pipeline arguments. Partial storage will carry them across requests.
        if self.id_token is not None:
            kwargs[_VALIDATED_ID_TOKEN_KEY] = self.id_token.copy()
        else:
            kwargs.pop(_VALIDATED_ID_TOKEN_KEY, None)
        return super().pipeline(pipeline, pipeline_index, *args, **kwargs)

    def continue_pipeline(
        self, partial: PartialMixin
    ) -> UserProtocol | HttpResponseProtocol | None:
        # Login already consumed the nonce. Restore the validated claims from
        # trusted partial storage rather than validating the token again.
        claims = partial.kwargs.get(_VALIDATED_ID_TOKEN_KEY)
        self.id_token = claims.copy() if isinstance(claims, dict) else None
        return super().continue_pipeline(partial)

    def get_setting_config(
        self,
        setting_name: str,
        oidc_name: str,
        default: str,
        *,
        stage: ErrorStage = "begin",
    ) -> str:
        value = self.setting(setting_name, default)
        if value is not None and not isinstance(value, str):
            raise AuthConfigurationError(
                self, parameter=setting_name, code="invalid_setting", stage=stage
            )
        if not value:
            try:
                value = self.oidc_config().get(oidc_name)
            except SocialAuthBaseException as error:
                error.stage = stage
                raise

        if not isinstance(value, str):
            raise AuthResponseError(
                self, claim=oidc_name, code="missing_claim", stage=stage
            )
        return value

    def authorization_url(self) -> str:
        return self.get_setting_config(
            "AUTHORIZATION_URL",
            "authorization_endpoint",
            self.AUTHORIZATION_URL,
            stage="begin",
        )

    def access_token_url(self) -> str:
        return self.get_setting_config(
            "ACCESS_TOKEN_URL",
            "token_endpoint",
            self.ACCESS_TOKEN_URL,
            stage="token_exchange",
        )

    def revoke_token_url(self, token, uid) -> str:
        return self.get_setting_config(
            "REVOKE_TOKEN_URL",
            "revocation_endpoint",
            self.REVOKE_TOKEN_URL,
            stage="disconnect",
        )

    def id_token_issuer(self) -> str:
        return self.get_setting_config(
            "ID_TOKEN_ISSUER", "issuer", self.ID_TOKEN_ISSUER, stage="token_validation"
        )

    def userinfo_url(self) -> str:
        return self.get_setting_config(
            "USERINFO_URL", "userinfo_endpoint", self.USERINFO_URL, stage="user_info"
        )

    def jwks_uri(self) -> str:
        return self.get_setting_config(
            "JWKS_URI", "jwks_uri", self.JWKS_URI, stage="token_validation"
        )

    def use_basic_auth(self) -> bool:
        method = self.setting(
            "TOKEN_ENDPOINT_AUTH_METHOD", self.TOKEN_ENDPOINT_AUTH_METHOD
        )
        if method:
            return method == "client_secret_basic"
        try:
            methods = self.oidc_config().get(
                "token_endpoint_auth_methods_supported", []
            )
        except SocialAuthBaseException as error:
            error.stage = "token_exchange"
            raise
        return not methods or "client_secret_basic" in methods

    def oidc_endpoint(self) -> str:
        return cast("str", self.setting("OIDC_ENDPOINT", self.OIDC_ENDPOINT))

    @cache(ttl=86400)
    def oidc_config(self) -> dict[Any, Any]:
        return load_oidc_config(
            self, f"{self.oidc_endpoint()}/.well-known/openid-configuration"
        )

    @cache(ttl=86400)
    def get_jwks_keys(self):
        return self.get_remote_jwks_keys()

        # Add client secret as oct key so it can be used for HMAC signatures
        # client_id, client_secret = self.get_key_and_secret()
        # keys.append({'key': client_secret, 'kty': 'oct'})

    def get_remote_jwks_keys(self):
        response = self.request(self.jwks_uri(), stage="token_validation")
        try:
            keys = loads(response.text)["keys"]
        except (ValueError, KeyError, TypeError) as error:
            raise AuthResponseError(
                self, code="malformed_response", stage="token_validation"
            ) from error
        if not isinstance(keys, list) or any(not isinstance(key, dict) for key in keys):
            raise AuthResponseError(
                self, code="malformed_response", stage="token_validation"
            )
        return keys

    def auth_params(self, state=None):  # noqa: C901, PLR0912
        """Return extra arguments needed on auth process."""
        params = super().auth_params(state)
        params["nonce"] = self.get_and_store_nonce(self.authorization_url(), state)

        display = self.setting("DISPLAY", default=self.DISPLAY)
        if display is not None:
            if not display:
                raise AuthConfigurationError(
                    self, parameter="display", code="invalid_setting", stage="begin"
                )

            if display not in ("page", "popup", "touch", "wap"):
                raise AuthConfigurationError(
                    self, parameter="display", code="invalid_setting", stage="begin"
                )

            params["display"] = display

        prompt = self.setting("PROMPT", default=self.PROMPT)
        if prompt is not None:
            if not prompt:
                raise AuthConfigurationError(
                    self, parameter="prompt", code="invalid_setting", stage="begin"
                )

            for prompt_token in prompt.split():
                if prompt_token not in ("none", "login", "consent", "select_account"):
                    raise AuthConfigurationError(
                        self, parameter="prompt", code="invalid_setting", stage="begin"
                    )

            params["prompt"] = prompt

        max_age = self.setting("MAX_AGE", default=self.MAX_AGE)
        if max_age is not None:
            if max_age < 0:
                raise AuthConfigurationError(
                    self, parameter="max_age", code="invalid_setting", stage="begin"
                )

            params["max_age"] = max_age

        ui_locales = self.setting("UI_LOCALES", default=self.UI_LOCALES)
        if ui_locales is not None:
            if not ui_locales:
                raise AuthConfigurationError(
                    self, parameter="ui_locales", code="invalid_setting", stage="begin"
                )

            params["ui_locales"] = ui_locales

        id_token_hint = self.setting("ID_TOKEN_HINT", default=self.ID_TOKEN_HINT)
        if id_token_hint is not None:
            if not id_token_hint:
                raise AuthConfigurationError(
                    self,
                    parameter="id_token_hint",
                    code="invalid_setting",
                    stage="begin",
                )

            params["id_token_hint"] = id_token_hint

        login_hint = self.setting("LOGIN_HINT", default=self.LOGIN_HINT)
        if login_hint is not None:
            if not login_hint:
                raise AuthConfigurationError(
                    self, parameter="login_hint", code="invalid_setting", stage="begin"
                )

            params["login_hint"] = login_hint

        acr_values = self.setting("ACR_VALUES", default=self.ACR_VALUES)
        if acr_values is not None:
            if not acr_values:
                raise AuthConfigurationError(
                    self, parameter="acr_values", code="invalid_setting", stage="begin"
                )

            params["acr_values"] = acr_values

        return params

    def get_and_store_nonce(self, url, state):
        # Create a nonce
        nonce = self.strategy.random_string(64)
        # Store the nonce
        association = OpenIdConnectAssociation(nonce, assoc_type=state)
        self.strategy.storage.association.store(url, association)
        return nonce

    def get_nonce(self, nonce):
        try:
            return self.strategy.storage.association.get(
                server_url=self.authorization_url(), handle=nonce
            )[0]
        except IndexError:
            return None

    def remove_nonce(self, nonce_id) -> None:
        self.strategy.storage.association.remove([nonce_id])

    def validate_temporal_claims(self, id_token) -> None:
        utc_timestamp = timegm(datetime.datetime.now(datetime.timezone.utc).timetuple())

        if "nbf" in id_token and utc_timestamp < id_token["nbf"]:
            raise AuthResponseError(
                self,
                "Incorrect id_token: nbf",
                code="response_not_yet_valid",
                stage="token_validation",
            )

        # Verify the token was issued in the last 10 minutes
        iat_leeway = self.setting("ID_TOKEN_MAX_AGE", self.ID_TOKEN_MAX_AGE)
        if "iat" not in id_token:
            raise AuthResponseError(
                self,
                "Missing id_token claim: iat",
                claim="iat",
                code="missing_claim",
                stage="token_validation",
            )
        if utc_timestamp > id_token["iat"] + iat_leeway:
            raise AuthResponseError(
                self,
                "Incorrect id_token: iat",
                claim="iat",
                code="response_expired",
                stage="token_validation",
            )

    def validate_claims(self, id_token) -> None:
        self.validate_temporal_claims(id_token)

        # Validate the nonce to ensure the request was not modified
        nonce = id_token.get("nonce")
        if not nonce:
            raise AuthResponseError(
                self,
                "Incorrect id_token: nonce",
                code="nonce_mismatch",
                stage="token_validation",
            )

        nonce_obj = self.get_nonce(nonce)
        if nonce_obj:
            self.remove_nonce(nonce_obj.id)
        else:
            raise AuthResponseError(
                self,
                "Incorrect id_token: nonce",
                code="nonce_mismatch",
                stage="token_validation",
            )

    def find_valid_key(self, id_token):
        kid = jwt.get_unverified_header(id_token).get("kid")

        keys = self.get_jwks_keys()
        if kid is not None:
            for key in keys:
                if kid == key.get("kid"):
                    break
            else:
                # In case the key id is not found in the cached keys, just
                # reload the JWKS keys. Ideally this should be done by
                # invalidating the cache.
                self.get_jwks_keys.invalidate()  # pyright: ignore[reportAttributeAccessIssue]
                keys = self.get_jwks_keys()

        for key in keys:
            if kid is None or kid == key.get("kid"):
                if "alg" not in key:
                    key["alg"] = cast(
                        "list[str]", self.setting("JWT_ALGORITHMS", self.JWT_ALGORITHMS)
                    )[0]
                rsakey = jwt.PyJWK(key)
                message, encoded_sig = id_token.rsplit(".", 1)
                decoded_sig = base64url_decode(encoded_sig.encode("utf-8"))
                if rsakey.Algorithm.verify(
                    message.encode("utf-8"), rsakey.key, decoded_sig
                ):
                    return key
        return None

    def decode_and_validate_id_token(self, id_token, access_token):
        """Validate an ID token's signature and self-contained claims."""
        client_id, _client_secret = self.get_key_and_secret()

        try:
            key = self.find_valid_key(id_token)
        except PyJWTError as error:
            raise jwt_error(self, error) from error

        if not key:
            raise AuthResponseError(
                self,
                "Signature verification failed",
                code="invalid_signature",
                stage="token_validation",
            )

        try:
            rsakey = jwt.PyJWK(key)
            claims = jwt.decode(
                id_token,
                rsakey.key,
                algorithms=self.setting("JWT_ALGORITHMS", self.JWT_ALGORITHMS),
                audience=client_id,
                issuer=self.id_token_issuer(),
                options=cast(
                    "Options",
                    self.setting("JWT_DECODE_OPTIONS", self.JWT_DECODE_OPTIONS),
                ),
                leeway=cast("int", self.setting("JWT_LEEWAY", self.JWT_LEEWAY)),
            )
        except ExpiredSignatureError as error:
            raise AuthResponseError(
                self,
                "Signature has expired",
                code="response_expired",
                stage="token_validation",
            ) from error
        except InvalidAudienceError as error:
            # compatibility with jose error message
            raise AuthResponseError(
                self,
                "Token error: Invalid audience",
                claim="aud",
                code="invalid_claim",
                stage="token_validation",
            ) from error
        except InvalidTokenError as error:
            raise jwt_error(self, error) from error
        except PyJWTError as error:
            raise jwt_error(self, error) from error

        # pyjwt does not validate OIDC claims
        # see https://github.com/jpadilla/pyjwt/pull/296
        self.validate_authorized_party(claims, client_id)
        if not self.validate_at_hash(claims, access_token, key):
            raise AuthResponseError(
                self,
                "Invalid access token",
                claim="at_hash",
                code="invalid_claim",
                stage="token_validation",
            )

        return claims

    def validate_and_return_id_token(self, id_token, access_token):
        """
        Validates the id_token according to the steps at
        http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
        """
        claims = self.decode_and_validate_id_token(id_token, access_token)
        self.validate_required_id_token_claims(claims)
        self.validate_claims(claims)

        return claims

    def validate_and_return_refresh_id_token(self, id_token, access_token):
        """Validate an ID token returned by a refresh request."""
        try:
            claims = self.decode_and_validate_id_token(id_token, access_token)
            self.validate_required_id_token_claims(claims)
            self.validate_temporal_claims(claims)
        except SocialAuthBaseException as error:
            # Preserve decoder overrides while reporting the active operation.
            error.stage = "refresh"
            raise

        return claims

    def request_access_token(  # noqa: PLR0913
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | None = None,
        json: dict | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
        *,
        stage: ErrorStage = "token_exchange",
    ) -> dict[Any, Any]:
        """
        Retrieve the access token. Also, validate the id_token and
        store it (temporarily).
        """
        response = super().request_access_token(
            url,
            method=method,
            stage=stage,
            headers=headers,
            data=data,
            json=json,
            auth=auth,
            params=params,
        )
        for parameter in ("id_token", "access_token"):
            token = response.get(parameter)
            if not isinstance(token, str) or not token:
                raise AuthResponseError(
                    self,
                    f"Missing {parameter} in OpenID Connect token response",
                    claim=parameter,
                    code="missing_claim",
                    stage="token_validation",
                )
        self.id_token = self.validate_and_return_id_token(
            response["id_token"], response["access_token"]
        )
        return response

    def process_refresh_token_response(self, response, *args, **kwargs) -> dict:
        data = super().process_refresh_token_response(response, *args, **kwargs)
        id_token = data.get("id_token")
        if id_token is None:
            return data

        for parameter in ("id_token", "access_token"):
            token = data.get(parameter)
            if not isinstance(token, str) or not token:
                raise AuthResponseError(
                    self,
                    f"Missing {parameter} in OpenID Connect refresh response",
                    claim=parameter,
                    code="missing_claim",
                    stage="refresh",
                )

        self.id_token = self.validate_and_return_refresh_id_token(
            id_token, data["access_token"]
        )
        return data

    @staticmethod
    def id_token_audiences(audience) -> set[str]:
        if isinstance(audience, str):
            return {audience}
        if isinstance(audience, list) and all(
            isinstance(item, str) for item in audience
        ):
            return set(cast("list[str]", audience))
        raise ValueError

    def validate_authorized_party(self, claims, client_id: str) -> None:
        """Validate the client authorized to use the ID token."""
        audience = claims.get("aud")
        if (
            isinstance(audience, list) and len(audience) > 1 and "azp" not in claims
        ) or ("azp" in claims and claims["azp"] != client_id):
            raise AuthResponseError(
                self,
                "Incorrect id_token: azp",
                claim="azp",
                code="invalid_claim",
                stage="token_validation",
            )

    def validate_required_id_token_claims(self, claims) -> None:
        """Validate claims required in every ID token."""
        for claim in ("iss", "sub", "aud", "exp"):
            if claim not in claims:
                raise AuthResponseError(
                    self,
                    f"Incorrect id_token: {claim}",
                    claim=claim,
                    code="missing_claim",
                    stage="token_validation",
                )

    @staticmethod
    def _id_token_context(claims) -> dict[str, Any]:
        """Return original claims used to validate refresh continuity."""
        context = {claim: claims[claim] for claim in ("iss", "sub", "aud")}
        for claim in ("auth_time", "nonce"):
            if claim in claims:
                context[claim] = claims[claim]
        return context

    def validate_refresh_id_token_claims(self, previous, current) -> None:
        """Validate identity continuity for an ID token refresh."""
        if not isinstance(previous, dict) or any(
            claim not in previous for claim in ("iss", "sub", "aud")
        ):
            raise AuthCredentialError(
                self, code="reauthentication_required", stage="refresh"
            )

        for claim in ("iss", "sub"):
            if previous[claim] != current[claim]:
                raise AuthResponseError(
                    self,
                    f"Incorrect refreshed id_token: {claim}",
                    claim=claim,
                    code="invalid_claim",
                    stage="refresh",
                )

        try:
            previous_audiences = self.id_token_audiences(previous["aud"])
        except ValueError as error:
            raise AuthCredentialError(
                self, code="reauthentication_required", stage="refresh"
            ) from error
        try:
            current_audiences = self.id_token_audiences(current["aud"])
        except ValueError as error:
            raise AuthResponseError(
                self, "Incorrect id_token: aud", code="invalid_claim", stage="refresh"
            ) from error
        if previous_audiences != current_audiences:
            raise AuthResponseError(
                self,
                "Incorrect refreshed id_token: aud",
                claim="aud",
                code="invalid_claim",
                stage="refresh",
            )

        for claim in ("auth_time", "nonce"):
            if claim in current and previous.get(claim) != current[claim]:
                raise AuthResponseError(
                    self,
                    f"Incorrect refreshed id_token: {claim}",
                    claim=claim,
                    code="invalid_claim",
                    stage="refresh",
                )

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        data = super().extra_data(user, uid, response, details, pipeline_kwargs)
        response_id_token = response.get("id_token")
        if response_id_token is not None:
            data["id_token"] = response_id_token
        elif "id_token" in details:
            data["id_token"] = details["id_token"]

        previous_context = details.get(_ID_TOKEN_CONTEXT_KEY)
        if pipeline_kwargs:
            if response_id_token is not None:
                if self.id_token is None:
                    raise AuthResponseError(
                        self,
                        "ID token was not validated",
                        code="invalid_claim",
                        stage="pipeline",
                    )
                data[_ID_TOKEN_CONTEXT_KEY] = self._id_token_context(self.id_token)
            return data

        if previous_context is not None:
            data[_ID_TOKEN_CONTEXT_KEY] = previous_context
        if response_id_token is None:
            return data
        if self.id_token is None:
            raise AuthResponseError(
                self,
                "ID token was not validated",
                code="invalid_claim",
                stage="refresh",
            )

        if previous_context is None:
            # Legacy associations have no original claim context. Their refreshes
            # were historically not continuity-checked, so establish the baseline
            # from this fully validated refresh token and enforce it thereafter.
            previous_context = self._id_token_context(self.id_token)
        else:
            self.validate_refresh_id_token_claims(previous_context, self.id_token)
        data[_ID_TOKEN_CONTEXT_KEY] = previous_context

        return data

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self.validate_userinfo_sub(
            self.get_json(
                self.userinfo_url(),
                headers={"Authorization": f"Bearer {access_token}"},
            )
        )

    def validate_userinfo_sub(
        self, userinfo: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Validate that UserInfo belongs to the validated ID token subject."""
        if userinfo is None or userinfo.get("sub") is None:
            return userinfo

        id_token_sub = self.id_token.get("sub") if self.id_token is not None else None
        if userinfo["sub"] != id_token_sub:
            raise AuthResponseError(
                self, "Invalid UserInfo sub", code="invalid_claim", stage="user_info"
            )

        return userinfo

    def get_user_id(self, details, response):
        id_key = self.id_key()
        if id_key == "sub":
            return self.get_user_id_from_sources(
                self.id_token, details, response, id_key=id_key
            )
        return self.get_user_id_from_sources(
            details, response, self.id_token, id_key=id_key
        )

    def get_user_groups(self, response) -> list[str] | None:
        key = configured_group_key(self)
        if key is None:
            return None
        source = self.id_token or {}
        check_group_overage(self, source, key)
        if key not in source:
            check_group_overage(self, response, key)
            if key in response:
                if not source.get("sub") or response.get("sub") != source["sub"]:
                    raise AuthResponseError(
                        self, code="invalid_claim", claim="sub", stage="user_info"
                    )
                source = response
        return read_groups(
            self,
            source,
            key,
            missing_as_empty=self.setting("GROUPS_MISSING_AS_EMPTY", False),
        )

    def get_user_details(self, response):
        """Return user details from the UserInfo response or ID token."""
        username_key = self.setting("USERNAME_KEY", self.USERNAME_KEY)
        email_key = self.setting("EMAIL_KEY", self.EMAIL_KEY)
        first_name_key = self.setting("FIRST_NAME_KEY", self.FIRST_NAME_KEY)
        last_name_key = self.setting("LAST_NAME_KEY", self.LAST_NAME_KEY)
        fullname_key = self.setting("FULLNAME_KEY", self.FULLNAME_KEY)

        def get_value(key):
            if key in response:
                return response.get(key)
            if self.id_token is not None:
                return self.id_token.get(key)
            return None

        return {
            "username": get_value(username_key),
            "email": get_value(email_key),
            "fullname": get_value(fullname_key),
            "first_name": get_value(first_name_key),
            "last_name": get_value(last_name_key),
        }

    def validate_at_hash(self, claims, access_token, key):
        """
        Validate the 'at_hash' claim according to OpenID Connect specs.

        See: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        """

        if not self.VALIDATE_AT_HASH:
            return True
        if "at_hash" not in claims:
            return True

        expected_hash = claims["at_hash"]
        calculated_hash = self.calc_at_hash(
            access_token, key["alg"], self.CUSTOM_AT_HASH_ALGO
        )
        return isinstance(expected_hash, str) and constant_time_compare(
            expected_hash, calculated_hash
        )

    @staticmethod
    def calc_at_hash(access_token, algorithm, custom_at_hash_algo: str | None = None):
        """
        Calculates "at_hash" claim which is not done by pyjwt.
        Custom "at_hash" algorithm is used for non-standard token.

        See https://pyjwt.readthedocs.io/en/stable/usage.html#oidc-login-flow
        See https://github.com/python-social-auth/social-core/issues/1306
        """

        if not custom_at_hash_algo:
            alg_obj = jwt.get_algorithm_by_name(algorithm)
            digest = alg_obj.compute_hash_digest(access_token.encode("utf-8"))
            return (
                base64.urlsafe_b64encode(digest[: (len(digest) // 2)])
                .decode("utf-8")
                .rstrip("=")
            )

        algo_class_name = custom_at_hash_algo.upper()
        algo_class = getattr(hashes, algo_class_name, None)
        if algo_class is None:
            raise NotImplementedError(
                f"Unsupported custom at hash algorithm: {custom_at_hash_algo}"
            )

        hasher = hashes.Hash(algo_class(), backend=default_backend())
        hasher.update(access_token.encode("utf-8"))
        digest = hasher.finalize()
        half = digest[: (len(digest) // 2)]
        return base64.urlsafe_b64encode(half).decode("utf-8").rstrip("=")
