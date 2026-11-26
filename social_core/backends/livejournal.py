"""
LiveJournal OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/livejournal.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urldefrag, urlsplit, urlunsplit

from social_core.backends.base import ResponseT_co
from social_core.exceptions import (
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
)
from social_core.utils import has_unsafe_url_characters

from .open_id import (
    OpenIdAuth,
    _discover_over_https,
    _HTTPSDiscoveryConsumer,
    _HTTPSDiscoveryGenericConsumer,
    _InsecureDiscovery,
)

if TYPE_CHECKING:
    from openid.consumer.consumer import SuccessResponse
    from openid.consumer.discover import OpenIDServiceEndpoint

    from social_core.store import OpenIdStore


def _discover_livejournal_claimed_id(
    identifier: str,
) -> tuple[str, list[OpenIDServiceEndpoint]]:
    """Verify legacy HTTP journal identities using LiveJournal's HTTPS page."""
    if has_unsafe_url_characters(identifier):
        raise _InsecureDiscovery("Unsafe LiveJournal claimed identifier", None)
    claimed_id = urldefrag(identifier).url
    try:
        parsed = urlsplit(claimed_id)
        port = parsed.port
    except ValueError as error:
        raise _InsecureDiscovery(
            "Invalid LiveJournal claimed identifier", None
        ) from error
    if parsed.scheme == "https":
        return _discover_over_https(identifier)
    invalid_host = (
        parsed.scheme != "http"
        or not parsed.hostname
        or not parsed.hostname.endswith(".livejournal.com")
        or parsed.username is not None
        or parsed.password is not None
    )
    invalid_shape = port is not None or bool(parsed.query)
    if invalid_host or invalid_shape:
        raise _InsecureDiscovery("Untrusted LiveJournal claimed identifier", None)
    secure_url = urlunsplit(("https", parsed.netloc, parsed.path, "", ""))
    _, services = _discover_over_https(secure_url)
    # Scheme changes identify different OpenID subjects. LiveJournal's own
    # HTTPS document must explicitly delegate to the asserted HTTP identity.
    matching = [service for service in services if service.getLocalID() == claimed_id]
    for service in matching:
        service.claimed_id = claimed_id
    return claimed_id, matching


class _LiveJournalGenericConsumer(_HTTPSDiscoveryGenericConsumer):
    _discover = staticmethod(_discover_livejournal_claimed_id)


class LiveJournalOpenId(OpenIdAuth[ResponseT_co]):
    """LiveJournal OpenID authentication backend"""

    name = "livejournal"
    title = "LiveJournal"
    # Discovery starts at the journal, which its owner can redirect to another
    # site. Only LiveJournal's own OpenID server may complete a login, and only
    # for an identity on LiveJournal.
    PROVIDER_HOST = "www.livejournal.com"
    JOURNAL_HOST_SUFFIX = ".livejournal.com"

    def create_consumer(
        self, store: OpenIdStore | None = None
    ) -> _HTTPSDiscoveryConsumer:
        session = self.strategy.openid_session_dict("openid")
        return _HTTPSDiscoveryConsumer(session, store, _LiveJournalGenericConsumer)

    def requires_openid_provider_binding(self) -> bool:
        return True

    @staticmethod
    def _hostname(url: object) -> str:
        if not isinstance(url, str):
            return ""
        try:
            return urlsplit(url).hostname or ""
        except ValueError:
            return ""

    def _validate_discovered_provider_endpoint(self, endpoint_url: object) -> None:
        super()._validate_discovered_provider_endpoint(endpoint_url)
        if self._hostname(endpoint_url) != self.PROVIDER_HOST:
            raise AuthProviderError(
                self,
                "OpenID discovery returned a provider endpoint outside LiveJournal",
                code="malformed_response",
                stage="begin",
            )

    def _validate_completed_provider(
        self, response: SuccessResponse, expected_endpoint: str
    ) -> None:
        super()._validate_completed_provider(response, expected_endpoint)
        if self._hostname(response.endpoint.server_url) != self.PROVIDER_HOST:
            raise AuthResponseError(
                self,
                "Verified OpenID provider is not LiveJournal",
                claim="op_endpoint",
                code="invalid_claim",
                stage="callback",
            )
        if not self._hostname(response.identity_url).endswith(self.JOURNAL_HOST_SUFFIX):
            raise AuthResponseError(
                self,
                "Verified OpenID identity is not a LiveJournal journal",
                claim="claimed_id",
                code="invalid_claim",
                stage="callback",
            )

    def get_user_details(self, response):
        """Generate username from identity url"""
        values = super().get_user_details(response)
        values["username"] = (
            values.get("username")
            or urlsplit(response.identity_url).netloc.split(".", 1)[0]
        )
        return values

    def openid_url(self) -> str:
        """Returns LiveJournal authentication URL"""
        username = self.data.get("openid_lj_user")
        if not username:
            raise AuthInputError(
                self,
                parameter="openid_lj_user",
                code="missing_parameter",
                stage="begin",
            )
        url = f"https://{username}.livejournal.com"
        try:
            parsed = urlsplit(url)
            valid_port = parsed.port is None
        except ValueError:
            parsed = None
            valid_port = False
        valid_host = (
            parsed is not None
            and parsed.hostname is not None
            and parsed.hostname.endswith(".livejournal.com")
        )
        valid_shape = (
            parsed is not None
            and valid_port
            and not any((parsed.path, parsed.query, parsed.fragment))
        )
        if not (self._is_https_url(url) and valid_host and valid_shape):
            raise AuthInputError(
                self,
                parameter="openid_lj_user",
                code="invalid_parameter",
                stage="begin",
            )
        return url
