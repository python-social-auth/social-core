# OpenID discovery and callbacks share the same protocol state and checks.
# pylint: disable=too-many-lines
from __future__ import annotations

import time
from calendar import timegm
from typing import TYPE_CHECKING, Any, cast
from urllib.error import URLError
from urllib.parse import parse_qsl, urldefrag, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, build_opener

from openid import fetchers
from openid.consumer.consumer import (
    CANCEL,
    FAILURE,
    SUCCESS,
    AuthRequest,
    Consumer,
    GenericConsumer,
    SuccessResponse,
)
from openid.consumer.discover import (
    DiscoveryFailure,
    OpenIDServiceEndpoint,
    getOPOrUserServices,
    normalizeURL,
)
from openid.extensions import ax, pape, sreg
from openid.fetchers import HTTPFetchingError
from openid.message import OPENID2_NS, OPENID_NS, Message
from openid.yadis.constants import YADIS_ACCEPT_HEADER
from openid.yadis.discover import DiscoveryResult, whereIsYadis
from openid.yadis.etxrd import XRDSError

from social_core.backends.base import ResponseT_co
from social_core.exceptions import (
    AuthCanceled,
    AuthConfigurationError,
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
    AuthUnknownError,
    ErrorStage,
)
from social_core.store import InvalidOpenIdSession, OpenIdSessionWrapper
from social_core.utils import (
    DEFAULT_REDIRECT_SCHEMES,
    constant_time_compare,
    has_unsafe_url_characters,
    url_add_parameters,
)

from .base import BaseAuth

if TYPE_CHECKING:
    from collections.abc import Collection

    from social_core.store import OpenIdStore

# OpenID configuration
OLD_AX_ATTRS = [
    ("http://schema.openid.net/contact/email", "old_email"),
    ("http://schema.openid.net/namePerson", "old_fullname"),
    ("http://schema.openid.net/namePerson/friendly", "old_nickname"),
]
AX_SCHEMA_ATTRS = [
    # Request both the full name and first/last components since some
    # providers offer one but not the other.
    ("http://axschema.org/contact/email", "email"),
    ("http://axschema.org/namePerson", "fullname"),
    ("http://axschema.org/namePerson/first", "first_name"),
    ("http://axschema.org/namePerson/last", "last_name"),
    ("http://axschema.org/namePerson/friendly", "nickname"),
]
SREG_ATTR = [("email", "email"), ("fullname", "fullname"), ("nickname", "nickname")]
OPENID_ID_FIELD = "openid_identifier"
SESSION_NAME = "openid"
_VERIFIED_RESPONSE_KEY = "_openid_verified_response"
_BACKEND_SESSION_KEY = "_social_auth_backend"
_LEGACY_SESSION_ID_FIELD = "psa_session_id"
# RFC 3339 UTC timestamp used by the PAPE auth_time response field.
_PAPE_AUTH_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _pape_now() -> int:
    """Read the PAPE clock through a private, testable binding."""
    return int(time.time())


def _is_https_url(url: object) -> bool:
    if not isinstance(url, str) or not url or has_unsafe_url_characters(url):
        return False
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and (port is None or port > 0)
    )


class _InsecureDiscovery(DiscoveryFailure):
    """Discovery of an HTTPS identifier left HTTPS."""


class _InsecureRedirect(URLError):
    """An OpenID discovery redirect tried to leave HTTPS."""


class _HTTPSRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib follows redirects inside the fetcher, before its caller can
        # inspect final_url. Reject the destination before urllib sends it.
        if not _is_https_url(newurl):
            raise _InsecureRedirect("OpenID discovery refers to an insecure URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _HTTPSDiscoveryFetcher(fetchers.Urllib2Fetcher):
    def __init__(self) -> None:
        # Construct the opener per fetch so environment proxy settings are
        # resolved for the current request, as with urllib's default opener.
        self.urlopen = cast("Any", build_opener(_HTTPSRedirectHandler()).open)


class _HTTPSCurlFetcher(fetchers.CurlHTTPFetcher):
    def _checkURL(self, url: str) -> bool:
        if not _is_https_url(url):
            raise _InsecureRedirect("OpenID discovery refers to an insecure URL")
        return super()._checkURL(url)


def _fetch_over_https(url: str, headers: dict[str, str] | None = None) -> Any:
    if not _is_https_url(url):
        raise _InsecureDiscovery("OpenID discovery refers to an insecure URL", None)
    try:
        current_fetcher = fetchers.getDefaultFetcher()
        while isinstance(current_fetcher, fetchers.ExceptionWrappingFetcher):
            current_fetcher = current_fetcher.fetcher
        if isinstance(current_fetcher, fetchers.HTTPLib2Fetcher):
            # httplib2 follows redirects internally without a per-hop guard.
            raise _InsecureDiscovery(
                "OpenID discovery fetcher cannot enforce HTTPS redirects", None
            )
        if isinstance(current_fetcher, fetchers.Urllib2Fetcher):
            secure_fetcher = _HTTPSDiscoveryFetcher()
        elif isinstance(current_fetcher, fetchers.CurlHTTPFetcher):
            secure_fetcher = _HTTPSCurlFetcher()
        else:
            # Custom fetchers are application-supplied transport boundaries.
            secure_fetcher = None
        response = (
            fetchers.ExceptionWrappingFetcher(secure_fetcher).fetch(
                url, headers=headers
            )
            if secure_fetcher is not None
            else fetchers.fetch(url, headers=headers)
        )
    except HTTPFetchingError as error:
        if isinstance(error.why, _InsecureRedirect):
            raise _InsecureDiscovery(
                "OpenID discovery refers to an insecure URL", None
            ) from error
        raise DiscoveryFailure("OpenID discovery request failed", None) from error
    except _InsecureRedirect as error:
        raise _InsecureDiscovery(
            "OpenID discovery refers to an insecure URL", None
        ) from error
    if not _is_https_url(response.final_url):
        raise _InsecureDiscovery(
            "OpenID discovery was redirected to an insecure URL", response
        )
    if response.status not in {200, 206}:
        raise DiscoveryFailure(
            f"OpenID discovery got HTTP status {response.status!r}", response
        )
    return response


def _discover_over_https(identifier: str) -> tuple[str, list[OpenIDServiceEndpoint]]:
    """Discover the services of an HTTPS identifier without leaving HTTPS.

    python3-openid follows redirects and the Yadis location of the identifier's
    page to ``http://`` URLs. The document found there names the provider and
    the local identifier it has to sign, so whoever can alter a cleartext
    response would choose who vouches for the HTTPS identifier. This is
    ``openid.consumer.discover.discoverURI`` with every fetch required to start
    and end at an HTTPS URL. Identifiers that are not HTTPS URLs are discovered
    as before.
    """
    if urlsplit(identifier).scheme != "https":
        raise _InsecureDiscovery("Fixed OpenID discovery requires HTTPS", None)

    endpoint_type = cast("Any", OpenIDServiceEndpoint)
    url = normalizeURL(identifier)
    result = DiscoveryResult(url)
    response = _fetch_over_https(url, {"Accept": YADIS_ACCEPT_HEADER})
    result.normalized_uri = response.final_url
    result.content_type = response.headers.get("content-type")
    result.xrds_uri = whereIsYadis(response)
    if result.xrds_uri and result.usedYadisLocation():
        response = _fetch_over_https(result.xrds_uri)
        # A fetcher reports where redirects ended, not the hops in between,
        # and a redirected document still speaks for the same identifier.
        if response.final_url != result.xrds_uri:
            raise _InsecureDiscovery("OpenID XRDS document was redirected", response)
        result.content_type = response.headers.get("content-type")

    try:
        services = endpoint_type.fromXRDS(result.normalized_uri, response.body)
    except XRDSError:
        services = []
    if not services:
        if result.isXRDS():
            # Not an OpenID XRDS document: read the page itself as HTML.
            page = _fetch_over_https(url)
            services = endpoint_type.fromHTML(page.final_url, page.body)
            return normalizeURL(page.final_url), services
        services = endpoint_type.fromHTML(result.normalized_uri, response.body)
    return normalizeURL(result.normalized_uri), cast(
        "list[OpenIDServiceEndpoint]", getOPOrUserServices(services)
    )


class _HTTPSDiscoveryGenericConsumer(GenericConsumer):
    _discover = staticmethod(_discover_over_https)


class _HTTPSDiscoveryConsumer(Consumer):
    _discover = staticmethod(_discover_over_https)


class OpenIdAuth(BaseAuth[ResponseT_co]):
    """Generic OpenID authentication backend"""

    name = "openid"
    title = "OpenID"
    URL: str | None = None
    USERNAME_KEY = "username"
    PROTOCOL_ID_KEY = "identity_url"

    _consumer = None

    def requires_openid_provider_binding(self) -> bool:
        """Return whether callbacks must use this backend's discovered provider."""
        return self.URL is not None

    @staticmethod
    def _is_web_url(
        url: object, schemes: Collection[str] = DEFAULT_REDIRECT_SCHEMES
    ) -> bool:
        if not isinstance(url, str) or not url or has_unsafe_url_characters(url):
            return False
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return False
        return (
            parsed.scheme in schemes
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
            and (port is None or port > 0)
        )

    @classmethod
    def _is_https_url(cls, url: object) -> bool:
        return cls._is_web_url(url, ("https",))

    def _validate_provider_url(self, url: object) -> None:
        if not self._is_https_url(url):
            raise AuthConfigurationError(
                self,
                "Fixed OpenID providers require an HTTPS URL",
                parameter="URL",
                code="invalid_setting",
                stage="begin",
            )

    def _validate_discovered_provider_endpoint(self, endpoint_url: object) -> None:
        if not isinstance(endpoint_url, str) or not endpoint_url:
            raise AuthProviderError(
                self,
                "OpenID discovery did not return a provider endpoint",
                code="malformed_response",
                stage="begin",
            )
        # The browser is sent to this endpoint by redirect or by the
        # auto-submitted form, so it must be an absolute HTTP(S) URL.
        if not self._is_web_url(endpoint_url):
            raise AuthProviderError(
                self,
                "OpenID discovery returned an invalid provider endpoint",
                code="malformed_response",
                stage="begin",
            )
        if self.requires_openid_provider_binding() and not self._is_https_url(
            endpoint_url
        ):
            raise AuthProviderError(
                self,
                "OpenID discovery returned an insecure provider endpoint",
                code="tls_error",
                stage="begin",
            )

    def _expected_openid_endpoint(self) -> OpenIDServiceEndpoint:
        try:
            session = self.strategy.openid_session_dict(SESSION_NAME)
            endpoint = session.get(OpenIdSessionWrapper.endpoint_key)
        except InvalidOpenIdSession as error:
            self.strategy.session_set(SESSION_NAME, {})
            self._consumer = None
            raise AuthSessionError(
                self,
                "OpenID authentication context is unavailable; restart login",
                code="session_context_missing",
                stage="callback",
            ) from error
        if (
            session.get(_BACKEND_SESSION_KEY) != self.name
            or not isinstance(endpoint, OpenIDServiceEndpoint)
            or not endpoint.server_url
        ):
            raise AuthSessionError(
                self,
                "OpenID authentication context is unavailable; restart login",
                code="session_context_missing",
                stage="callback",
            )
        return endpoint

    def _expected_provider_endpoint(self) -> str:
        endpoint_url = self._expected_openid_endpoint().server_url
        if not self._is_https_url(endpoint_url):
            raise AuthResponseError(
                self,
                "OpenID provider endpoint is insecure",
                claim="op_endpoint",
                code="invalid_claim",
                stage="callback",
            )
        return cast("str", endpoint_url)

    def _isolated_callback_consumer(self) -> Consumer:
        session = OpenIdSessionWrapper()
        try:
            current_session = self.strategy.openid_session_dict(SESSION_NAME)
            if current_session.get(_BACKEND_SESSION_KEY) == self.name:
                endpoint = current_session.get(OpenIdSessionWrapper.endpoint_key)
                if isinstance(endpoint, OpenIDServiceEndpoint):
                    session[OpenIdSessionWrapper.endpoint_key] = endpoint
        except InvalidOpenIdSession:
            # Verification below must run in isolation even when the browser's
            # existing OpenID state cannot be decoded.
            pass
        return Consumer(session, self.get_consumer_store())

    def _complete_generic_response(self):
        return self._isolated_callback_consumer().complete(
            dict(self.data.items()), self.get_return_to()
        )

    def _validate_signed_return_to(self, response: SuccessResponse) -> None:
        return_to = response.message.getArg(OPENID_NS, "return_to")
        if (
            "openid.return_to" not in response.signed_fields
            or not isinstance(return_to, str)
            or not return_to
        ):
            raise AuthResponseError(
                self,
                "OpenID return URL is not signed",
                claim="return_to",
                code="invalid_claim",
                stage="callback",
            )
        try:
            session_ids = [
                value
                for key, value in parse_qsl(
                    urlsplit(return_to).query, keep_blank_values=True
                )
                if key == _LEGACY_SESSION_ID_FIELD
            ]
        except ValueError as error:
            raise AuthResponseError(
                self,
                "OpenID return URL is malformed",
                claim="return_to",
                code="invalid_claim",
                stage="callback",
            ) from error

        if session_ids or self.data.get(_LEGACY_SESSION_ID_FIELD) is not None:
            raise AuthResponseError(
                self,
                "OpenID session restoration is no longer supported",
                claim=_LEGACY_SESSION_ID_FIELD,
                code="invalid_claim",
                stage="callback",
            )

    @staticmethod
    def _claimed_id(identifier: object) -> str | None:
        if not isinstance(identifier, str) or not identifier:
            return None
        return urldefrag(identifier).url

    def _validate_completed_generic_provider(
        self,
        response: SuccessResponse,
        expected_endpoint: OpenIDServiceEndpoint,
    ) -> None:
        verified_endpoint = response.endpoint
        if verified_endpoint.server_url != expected_endpoint.server_url:
            raise AuthResponseError(
                self,
                "Verified OpenID provider does not match the initiated provider",
                claim="op_endpoint",
                code="invalid_claim",
                stage="callback",
            )
        verified_claimed_id = self._claimed_id(verified_endpoint.claimed_id)
        if expected_endpoint.isOPIdentifier():
            if verified_claimed_id is None:
                raise AuthResponseError(
                    self,
                    "Verified OpenID response is missing its claimed identity",
                    claim="claimed_id",
                    code="invalid_claim",
                    stage="callback",
                )
            return
        if verified_claimed_id is None or verified_claimed_id != self._claimed_id(
            expected_endpoint.claimed_id
        ):
            raise AuthResponseError(
                self,
                "Verified OpenID identity does not match the initiated identity",
                claim="claimed_id",
                code="invalid_claim",
                stage="callback",
            )
        if verified_endpoint.getLocalID() != expected_endpoint.getLocalID():
            raise AuthResponseError(
                self,
                "Verified OpenID local identity does not match the initiated identity",
                claim="identity",
                code="invalid_claim",
                stage="callback",
            )

    def _clear_openid_context(self) -> None:
        try:
            session = self.strategy.openid_session_dict(SESSION_NAME)
        except InvalidOpenIdSession:
            self.strategy.session_set(SESSION_NAME, {})
            self._consumer = None
            return
        for key in (
            OpenIdSessionWrapper.endpoint_key,
            OpenIdSessionWrapper.manager_key,
            _BACKEND_SESSION_KEY,
        ):
            session.pop(key, None)
        self._consumer = None

    def _validate_callback_provider(self, expected_endpoint: str) -> None:
        callback_endpoint = self.data.get("openid.op_endpoint")
        if not callback_endpoint:
            raise AuthResponseError(
                self,
                "OpenID provider endpoint is missing",
                claim="op_endpoint",
                code="missing_claim",
                stage="callback",
            )
        if (
            not self._is_https_url(callback_endpoint)
            or callback_endpoint != expected_endpoint
        ):
            raise AuthResponseError(
                self,
                "OpenID provider endpoint does not match the initiated provider",
                claim="op_endpoint",
                code="invalid_claim",
                stage="callback",
            )

    def _validate_completed_provider(
        self, response: SuccessResponse, expected_endpoint: str
    ) -> None:
        if response.endpoint.server_url != expected_endpoint:
            raise AuthResponseError(
                self,
                "Verified OpenID provider does not match the initiated provider",
                claim="op_endpoint",
                code="invalid_claim",
                stage="callback",
            )

    def get_user_id(self, details, response):
        """Return the protocol-defined identity URL provided by the service.

        OpenID identity is asserted as a URL rather than a response mapping field,
        so the configurable ID_KEY does not apply to this backend.
        """
        return response.identity_url

    def get_user_id_for_key(self, details, response, id_key: str):
        """Return the asserted identity URL or an explicitly selected profile field."""
        if id_key == self.PROTOCOL_ID_KEY:
            return response.identity_url
        return self.get_user_id_from_sources(details, id_key=id_key)

    def get_ax_attributes(self) -> list[tuple[str, str]]:
        attrs = cast("list[tuple[str, str]]", self.setting("AX_SCHEMA_ATTRS", []))
        if attrs and self.setting("IGNORE_DEFAULT_AX_ATTRS", True):
            return attrs
        return attrs + AX_SCHEMA_ATTRS + OLD_AX_ATTRS

    def get_sreg_attributes(self):
        return self.setting("SREG_ATTR") or SREG_ATTR

    def values_from_response(self, response, sreg_names=None, ax_names=None):
        """Return values from SimpleRegistration response or
        AttributeExchange response if present.

        @sreg_names and @ax_names must be a list of name and aliases
        for such name. The alias will be used as mapping key.
        """
        values: dict[str, str | None] = {}
        name_fields = {"fullname", "first_name", "last_name"}

        # Use Simple Registration attributes if provided
        if sreg_names:
            resp = cast("Any", sreg.SRegResponse).fromSuccessResponse(response)
            if resp:
                values.update(
                    (
                        alias,
                        resp.get(name)
                        if alias in name_fields
                        else resp.get(name) or "",
                    )
                    for name, alias in sreg_names
                )

        # Use Attribute Exchange attributes if provided
        if ax_names and response.extensionResponse(ax.AXMessage.ns_uri, True):
            resp = cast("Any", ax.FetchResponse).fromSuccessResponse(response)
            if resp:
                for src, alias in ax_names:
                    name = alias.replace("old_", "")
                    if name in name_fields:
                        value = cast("str | None", resp.getSingle(src, None))
                        # An empty alias must not replace a usable earlier name.
                        if value is not None and (
                            value.strip() or not values.get(name)
                        ):
                            values[name] = value
                    else:
                        values[name] = cast(
                            "str | None", resp.getSingle(src, "")
                        ) or values.get(name, "")

        return values

    def get_user_details(self, response):
        """Return user details from an OpenID request"""
        values: dict[str, str | None] = {
            "username": "",
            "email": "",
            "fullname": None,
            "first_name": None,
            "last_name": None,
        }
        # update values using SimpleRegistration or AttributeExchange
        # values
        values.update(
            self.values_from_response(
                response, self.get_sreg_attributes(), self.get_ax_attributes()
            )
        )

        fullname = values.get("fullname")
        first_name = values.get("first_name")
        last_name = values.get("last_name")
        email = values.get("email") or ""

        username_first, username_last = first_name or "", last_name or ""
        if fullname:
            try:
                username_first, username_last = fullname.rsplit(" ", 1)
            except ValueError:
                username_last = fullname

        username_key = cast("str", self.setting("USERNAME_KEY") or self.USERNAME_KEY)
        values.update(
            {
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
                "username": values.get(username_key)
                or (username_first.title() + username_last.title()),
                "email": email,
            }
        )
        return values

    def auth_allowed(self, response: Any, details: dict[str, Any]) -> bool:
        """Return True if the user should be allowed to authenticate.

        A provider selected by the visitor vouches only for its own
        identifiers, so the address it asserts cannot satisfy
        WHITELISTED_EMAILS or WHITELISTED_DOMAINS.
        """
        if not self.requires_openid_provider_binding():
            details = {**details, "email": ""}
        return super().auth_allowed(response, details)

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Return defined extra data names to store in extra_data field.
        Settings will be inspected to get more values names that should be
        stored on extra_data field. Setting name is created from current
        backend name (all uppercase) plus _SREG_EXTRA_DATA and
        _AX_EXTRA_DATA because values can be returned by SimpleRegistration
        or AttributeExchange schemas.

        Both list must be a value name and an alias mapping similar to
        SREG_ATTR, OLD_AX_ATTRS or AX_SCHEMA_ATTRS
        """
        sreg_names = self.setting("SREG_EXTRA_DATA")
        ax_names = self.setting("AX_EXTRA_DATA")
        values = self.values_from_response(response, sreg_names, ax_names)
        from_details = super().extra_data(user, uid, {}, details, pipeline_kwargs)
        values.update(from_details)
        return values

    def get_return_to(self) -> str:
        return self.strategy.absolute_uri(self.redirect_uri)

    @staticmethod
    def _add_return_to_parameters(url: str, params: dict[str, str]) -> str:
        if not params:
            return url
        parsed = urlsplit(url)
        query = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key not in params
        ]
        query.extend(params.items())
        return urlunsplit(parsed._replace(query=urlencode(query)))

    def _return_to_for_login(self) -> str:
        return self._add_return_to_parameters(
            self.get_return_to(), {"redirect_state": self.create_state()}
        )

    def create_state(self) -> str:
        """Bind the next positive assertion to this browser's OpenID login."""
        state = self.strategy.random_string(32)
        self.strategy.session_set(f"{self.name}_state", state)
        return state

    def answers_pending_request(self, data: dict[str, Any]) -> bool:
        state = data.get("redirect_state")
        pending = self.strategy.session_get(f"{self.name}_state")
        if isinstance(pending, dict):
            pending = pending.get("state")
        return (
            isinstance(state, str)
            and isinstance(pending, str)
            and bool(state)
            and constant_time_compare(state, pending)
        )

    def validate_state(self) -> None:
        """Require the verified return URL's state in the initiating session."""
        request_state = self.data.get("redirect_state")
        if not isinstance(request_state, str) or not request_state:
            raise AuthInputError(
                self,
                parameter="redirect_state",
                code="missing_parameter",
                stage="callback",
            )
        name = f"{self.name}_state"
        session_state = self.strategy.session_get(name)
        if not isinstance(session_state, str) or not session_state:
            raise AuthSessionError(
                self, "state", code="session_context_missing", stage="callback"
            )
        if not constant_time_compare(request_state, session_state):
            raise AuthSessionError(self, code="state_mismatch", stage="callback")
        self.strategy.session_pop(name)

    def auth_url(self):
        """Return auth URL returned by service"""
        openid_request = self.setup_request(self.auth_extra_arguments())
        # Construct completion URL, including page we should redirect to
        return openid_request.redirectURL(
            self.trust_root(), self._return_to_for_login()
        )

    def auth_html(self):
        """Return auth HTML returned by service"""
        openid_request = self.setup_request(self.auth_extra_arguments())
        form_tag = {"id": "openid_message"}
        return openid_request.htmlMarkup(
            self.trust_root(),
            self._return_to_for_login(),
            form_tag_attrs=form_tag,
        )

    def trust_root(self):
        """Return trust-root option"""
        return self.setting("OPENID_TRUST_ROOT") or self.strategy.absolute_uri("/")

    @staticmethod
    def _restore_verified_response(snapshot):
        if not isinstance(snapshot, dict):
            raise TypeError
        endpoint_data = snapshot["endpoint"]
        message = snapshot["message"]
        signed_fields = snapshot["signed_fields"]
        if (
            not isinstance(endpoint_data, dict)
            or not isinstance(endpoint_data.get("claimed_id"), str)
            or not endpoint_data["claimed_id"]
        ):
            raise ValueError
        if not isinstance(message, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in message.items()
        ):
            raise ValueError
        if not isinstance(signed_fields, list) or not all(
            isinstance(field, str) for field in signed_fields
        ):
            raise ValueError
        endpoint = OpenIDServiceEndpoint()
        vars(endpoint).update(endpoint_data)
        return SuccessResponse(endpoint, Message.fromPostArgs(message), signed_fields)

    def continue_pipeline(self, partial):
        """Continue previous halted pipeline"""
        try:
            response = self._restore_verified_response(
                partial.kwargs.get(_VERIFIED_RESPONSE_KEY)
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AuthSessionError(
                self,
                "OpenID authentication context is unavailable; restart login",
                code="session_context_missing",
                stage="callback",
            ) from error
        kwargs = partial.kwargs.copy()
        kwargs["response"] = response
        with self._partial_pipeline_context(partial):
            return self.strategy.authenticate(
                self,
                *partial.args,
                pipeline_index=partial.next_step,
                **kwargs,
            )

    def auth_complete(self, *args, **kwargs):
        """Complete auth process"""
        expected_endpoint = None
        if (
            self.requires_openid_provider_binding()
            and self.data.get("openid.mode") == "id_res"
        ):
            expected_endpoint = self._expected_provider_endpoint()
            if self.data.get("openid.ns") == OPENID2_NS:
                self._validate_callback_provider(expected_endpoint)
        try:
            if (
                not self.requires_openid_provider_binding()
                and self.data.get("openid.mode") == "id_res"
            ):
                response = self._complete_generic_response()
            else:
                response = self.consumer().complete(
                    dict(self.data.items()), self.get_return_to()
                )
        except InvalidOpenIdSession as error:
            self.strategy.session_set(SESSION_NAME, {})
            self._consumer = None
            raise AuthSessionError(
                self,
                "OpenID authentication context is unavailable; restart login",
                code="session_context_missing",
                stage="callback",
            ) from error
        except HTTPFetchingError as error:
            raise AuthProviderError(
                self, code="connection_failed", stage="callback"
            ) from error

        self.process_error(response)
        response = cast("SuccessResponse", response)
        self._validate_signed_return_to(response)
        if self.requires_openid_provider_binding():
            if expected_endpoint is None:
                raise AuthSessionError(
                    self,
                    "OpenID authentication context is unavailable; restart login",
                    code="session_context_missing",
                    stage="callback",
                )
            self._validate_completed_provider(response, expected_endpoint)
        else:
            initiated_endpoint = self._expected_openid_endpoint()
            self._validate_completed_generic_provider(response, initiated_endpoint)
        self.validate_state()
        self.validate_pape_auth_time(response)
        self._clear_openid_context()
        # Retain both the verified message and its signed fields so extension
        # data keeps the same trust checks after a JSON-serialized partial.
        kwargs[_VERIFIED_RESPONSE_KEY] = {
            "endpoint": vars(response.endpoint).copy(),
            "message": response.message.toPostArgs(),
            "signed_fields": list(response.signed_fields),
        }
        return self.strategy.authenticate(self, *args, response=response, **kwargs)

    def process_error(self, data, *, stage: ErrorStage = "callback") -> None:
        if not data:
            raise AuthResponseError(
                self,
                "OpenID relying party endpoint",
                code="malformed_response",
                stage=stage,
            )
        if data.status == FAILURE:
            raise AuthResponseError(
                self, data.message, code="malformed_response", stage=stage
            )
        if data.status == CANCEL:
            raise AuthCanceled(self, code="authorization_declined", stage=stage)
        if data.status != SUCCESS:
            raise AuthUnknownError(self, data.status, code="unknown_error", stage=stage)

    def setup_request(self, params=None):
        """Setup request"""
        request = self.openid_request(params)
        # Request some user details. Use attribute exchange if provider
        # advertises support.
        if request.endpoint.supportsType(ax.AXMessage.ns_uri):
            fetch_request = ax.FetchRequest()
            # Mark all attributes as required, Google ignores optional ones
            for attr, alias in self.get_ax_attributes():
                fetch_request.add(ax.AttrInfo(attr, alias=alias, required=True))
        else:
            fetch_request = sreg.SRegRequest(
                optional=list(dict(self.get_sreg_attributes()).keys())
            )
        request.addExtension(fetch_request)

        self.add_pape_request(request)
        return request

    def add_pape_request(self, request: AuthRequest) -> None:
        """Attach the configured PAPE request and remember when it was sent."""
        preferred_policies = self.setting("OPENID_PAPE_PREFERRED_AUTH_POLICIES")
        preferred_level_types = self.setting("OPENID_PAPE_PREFERRED_AUTH_LEVEL_TYPES")
        max_age = self.pape_max_auth_age()
        if max_age is not None:
            # max_auth_age counts back from this request; the callback
            # compares the signed auth_time against that moment.
            self.strategy.session_set(f"{self.name}_pape_requested_at", _pape_now())

        if max_age is not None or preferred_policies or preferred_level_types:
            pape_request = pape.Request(
                max_auth_age=max_age,
                preferred_auth_policies=preferred_policies,
                preferred_auth_level_types=preferred_level_types,
            )
            request.addExtension(pape_request)

    def pape_max_auth_age(self) -> int | None:
        """Return the configured PAPE max_auth_age in seconds, if any."""
        max_age = self.setting("OPENID_PAPE_MAX_AUTH_AGE")
        if max_age is None:
            return None
        try:
            parsed = int(max_age)
        except (ValueError, TypeError) as error:
            raise AuthConfigurationError(
                self,
                code="invalid_setting",
                parameter="OPENID_PAPE_MAX_AUTH_AGE",
                stage="begin",
            ) from error
        if isinstance(max_age, bool) or parsed < 0:
            raise AuthConfigurationError(
                self,
                code="invalid_setting",
                parameter="OPENID_PAPE_MAX_AUTH_AGE",
                stage="begin",
            )
        return parsed

    def validate_pape_auth_time(self, response: SuccessResponse) -> None:
        """Require a signed PAPE auth_time within OPENID_PAPE_MAX_AUTH_AGE.

        The authentication request reaches the provider through the browser,
        which can drop or alter max_auth_age, and a provider may ignore it,
        so the provider's signed answer has to show the requirement was met.
        """
        requested_at = self.strategy.session_pop(f"{self.name}_pape_requested_at")
        max_age = self.pape_max_auth_age()
        if max_age is None:
            return
        # fromSuccessResponse() only reads signed PAPE fields.
        pape_response = cast("Any", pape.Response).fromSuccessResponse(response)
        auth_time = pape_response.auth_time if pape_response else None
        if not auth_time:
            raise AuthResponseError(
                self,
                "Missing PAPE response: auth_time",
                claim="auth_time",
                code="missing_claim",
                stage="callback",
            )
        try:
            authenticated_at = timegm(time.strptime(auth_time, _PAPE_AUTH_TIME_FORMAT))
        except ValueError as error:
            raise AuthResponseError(
                self,
                "Incorrect PAPE response: auth_time",
                claim="auth_time",
                code="invalid_claim",
                stage="callback",
            ) from error
        if not isinstance(requested_at, int):
            # The request was made without the setting; fail safe on now.
            requested_at = _pape_now()
        leeway = self.setting("OPENID_PAPE_AUTH_TIME_LEEWAY", 1)
        if not isinstance(leeway, int) or isinstance(leeway, bool) or leeway < 0:
            raise AuthConfigurationError(
                self,
                code="invalid_setting",
                parameter="OPENID_PAPE_AUTH_TIME_LEEWAY",
                stage="callback",
            )
        if authenticated_at > _pape_now() + leeway:
            raise AuthResponseError(
                self,
                "Incorrect PAPE response: auth_time",
                claim="auth_time",
                code="response_not_yet_valid",
                stage="callback",
            )
        if requested_at - authenticated_at > max_age:
            raise AuthResponseError(
                self,
                "Incorrect PAPE response: auth_time",
                claim="auth_time",
                code="response_expired",
                stage="callback",
            )

    def get_consumer_store(self) -> OpenIdStore | None:
        return self.strategy.openid_store()

    def consumer(self):
        """Create an OpenID Consumer object for the given Django request."""
        if self._consumer is None:
            self._consumer = self.create_consumer(self.get_consumer_store())
        return self._consumer

    def create_consumer(self, store=None):
        session = self.strategy.openid_session_dict(SESSION_NAME)
        if self.requires_openid_provider_binding():
            return _HTTPSDiscoveryConsumer(
                session, store, _HTTPSDiscoveryGenericConsumer
            )
        return Consumer(session, store)

    def uses_redirect(self):
        """Return true if openid request will be handled with redirect or
        HTML content will be returned.
        """
        return self.openid_request().shouldSendRedirect()

    def _begin_openid_request(
        self, provider_url: str, params: dict[str, str] | None
    ) -> AuthRequest:
        try:
            session = self.strategy.openid_session_dict(SESSION_NAME)
            same_backend = session.get(_BACKEND_SESSION_KEY) == self.name
        except InvalidOpenIdSession:
            same_backend = False
        if not same_backend:
            # Discovery stores the endpoint as it goes and can fail half-way,
            # so drop another backend's context and claim the session before
            # it starts. The consumer persists its own copy of the session,
            # so it must be recreated from the claimed one.
            self.strategy.session_set(SESSION_NAME, {_BACKEND_SESSION_KEY: self.name})
            self._consumer = None
        consumer = self.consumer()
        if self.requires_openid_provider_binding():
            # Previously saved services may have been discovered over HTTP.
            consumer.session.pop(OpenIdSessionWrapper.manager_key, None)
        request = consumer.begin(url_add_parameters(provider_url, params))
        try:
            self._validate_discovered_provider_endpoint(request.endpoint.server_url)
        except AuthProviderError:
            self.strategy.session_set(SESSION_NAME, {})
            self._consumer = None
            raise
        self.strategy.openid_session_dict(SESSION_NAME)[_BACKEND_SESSION_KEY] = (
            self.name
        )
        return request

    def openid_request(self, params: dict[str, str] | None = None) -> AuthRequest:
        """Return openid request"""
        provider_url = self.openid_url()
        if self.requires_openid_provider_binding():
            self._validate_provider_url(provider_url)
        try:
            return self._begin_openid_request(provider_url, params)
        except DiscoveryFailure as err:
            raise AuthProviderError(
                self,
                f"OpenID discovery error: {err}",
                code="tls_error"
                if isinstance(err, _InsecureDiscovery)
                else "http_error",
                stage="begin",
            ) from err

    def openid_url(self):
        """Return service provider URL.
        This base class is generic accepting a POST parameter that specifies
        provider URL."""
        if self.URL:
            return self.URL
        if OPENID_ID_FIELD in self.data:
            return self.data[OPENID_ID_FIELD]
        raise AuthInputError(
            self, parameter=OPENID_ID_FIELD, code="missing_parameter", stage="begin"
        )
