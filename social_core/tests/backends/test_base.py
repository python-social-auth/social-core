from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
import responses

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthConfigurationError, AuthProviderError
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy

if TYPE_CHECKING:
    from pathlib import Path

    from social_core.strategy import BaseStrategy


class ExampleAuth(BaseAuth):
    name = "example"


def get_backend(settings, request_data=None):
    strategy = TestStrategy(TestStorage)
    backend = ExampleAuth(strategy)
    strategy.set_settings(settings)
    if request_data is not None:
        strategy.set_request_data(request_data, backend)
    return backend


def test_auth_extra_arguments_ignore_matching_request_parameters_by_default() -> None:
    backend = get_backend(
        {
            "SOCIAL_AUTH_EXAMPLE_AUTH_EXTRA_ARGUMENTS": {
                "audience": "configured-audience",
                "resource": "configured-resource",
            }
        },
        {
            "audience": "request-audience",
            "resource": "request-resource",
        },
    )

    assert backend.auth_extra_arguments() == {
        "audience": "configured-audience",
        "resource": "configured-resource",
    }


def test_auth_extra_arguments_allowlisted_key_can_use_request_parameter() -> None:
    backend = get_backend(
        {
            "SOCIAL_AUTH_EXAMPLE_AUTH_EXTRA_ARGUMENTS": {
                "audience": "configured-audience",
                "prompt": "login",
                "resource": "configured-resource",
            },
            "SOCIAL_AUTH_EXAMPLE_AUTH_EXTRA_ARGUMENTS_OVERRIDE_ALLOWLIST": ["prompt"],
        },
        {
            "audience": "request-audience",
            "prompt": "select_account",
            "resource": "request-resource",
        },
    )

    assert backend.auth_extra_arguments() == {
        "audience": "configured-audience",
        "prompt": "select_account",
        "resource": "configured-resource",
    }


def test_auth_extra_arguments_request_only_keys_are_not_added() -> None:
    backend = get_backend(
        {
            "SOCIAL_AUTH_EXAMPLE_AUTH_EXTRA_ARGUMENTS": {"prompt": "login"},
            "SOCIAL_AUTH_EXAMPLE_AUTH_EXTRA_ARGUMENTS_OVERRIDE_ALLOWLIST": [
                "prompt",
                "audience",
            ],
        },
        {
            "audience": "request-audience",
            "prompt": "select_account",
        },
    )

    assert backend.auth_extra_arguments() == {"prompt": "select_account"}


def authenticate_kwargs(strategy: BaseStrategy, backend: BaseAuth) -> dict[str, Any]:
    return {
        "strategy": strategy,
        "storage": TestStorage,
        "backend": backend,
        "response": {},
    }


def test_authenticate_runs_pipeline_on_the_given_backend() -> None:
    backend = get_backend({})
    # A framework's authentication API may create its own instance of each
    # configured backend class, with the default strategy.
    default_strategy = TestStrategy(TestStorage)
    candidate = ExampleAuth(default_strategy)

    with (
        patch.object(
            ExampleAuth, "pipeline", autospec=True, return_value=None
        ) as pipeline,
        warnings.catch_warnings(),
    ):
        warnings.simplefilter("error", DeprecationWarning)
        candidate.authenticate(**authenticate_kwargs(backend.strategy, backend))

    pipeline.assert_called_once()
    assert pipeline.call_args.args[0] is backend
    assert candidate.strategy is default_strategy


def test_authenticate_rejects_backend_bound_to_another_strategy() -> None:
    backend = get_backend({})
    original_strategy = backend.strategy
    other_strategy = TestStrategy(TestStorage)

    with (
        patch.object(ExampleAuth, "pipeline") as pipeline,
        pytest.raises(AuthConfigurationError) as caught,
    ):
        backend.authenticate(**authenticate_kwargs(other_strategy, backend))

    assert caught.value.code == "unsupported_feature"
    assert caught.value.parameter == "strategy"
    assert caught.value.stage == "callback"
    pipeline.assert_not_called()
    assert backend.strategy is original_strategy


def test_assigning_strategy_is_deprecated() -> None:
    backend = get_backend({})
    other_strategy = TestStrategy(TestStorage)

    # Type checkers reject assigning the property, so assign it dynamically.
    attribute = "strategy"
    with pytest.warns(DeprecationWarning, match=r"BaseAuth\.strategy"):
        setattr(backend, attribute, other_strategy)

    assert backend.strategy is other_strategy


@responses.activate
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_request_refuses_redirect_from_https_to_http(status: int) -> None:
    responses.add(
        responses.POST,
        "https://provider.example/token",
        status=status,
        headers={"Location": "http://provider.example/token"},
    )
    responses.add(responses.GET, "http://provider.example/token", json={})
    responses.add(responses.POST, "http://provider.example/token", json={})

    with pytest.raises(AuthProviderError) as caught:
        get_backend({}).request(
            "https://provider.example/token",
            method="POST",
            data={"client_secret": "secret"},
            stage="token_exchange",
        )

    assert caught.value.code == "tls_error"
    assert caught.value.stage == "token_exchange"
    assert [call.request.url for call in responses.calls] == [
        "https://provider.example/token"
    ]


@responses.activate
@pytest.mark.parametrize(
    "location",
    [
        "HTTP://provider.example/user",
        # Requests unquotes the location before resolving it
        "%68ttp://provider.example/user",
        # urllib drops tabs while Requests parses the location
        "ht\ttp://provider.example/user",
        "ftp://provider.example/user",
    ],
)
def test_request_refuses_redirect_to_resolved_insecure_url(location: str) -> None:
    responses.add(
        responses.GET,
        "https://provider.example/user",
        status=302,
        headers={"Location": location},
    )
    responses.add(responses.GET, "http://provider.example/user", json={})

    with pytest.raises(AuthProviderError) as caught:
        get_backend({}).request("https://provider.example/user")

    assert caught.value.code == "tls_error"
    assert len(responses.calls) == 1


@responses.activate
def test_request_refuses_redirect_to_http_after_https_redirect() -> None:
    responses.add(
        responses.GET,
        "https://provider.example/user",
        status=302,
        headers={"Location": "https://www.provider.example/user"},
    )
    responses.add(
        responses.GET,
        "https://www.provider.example/user",
        status=302,
        headers={"Location": "http://www.provider.example/user"},
    )
    responses.add(responses.GET, "http://www.provider.example/user", json={})

    with pytest.raises(AuthProviderError) as caught:
        get_backend({}).request("https://provider.example/user")

    assert caught.value.code == "tls_error"
    assert len(responses.calls) == 2


@responses.activate
@pytest.mark.parametrize(
    ("url", "location", "target"),
    [
        (
            "https://provider.example/user",
            "https://www.provider.example/user",
            "https://www.provider.example/user",
        ),
        (
            "https://provider.example/user",
            "/users/1",
            "https://provider.example/users/1",
        ),
        (
            "https://provider.example/user",
            "//www.provider.example/user",
            "https://www.provider.example/user",
        ),
        (
            "http://provider.example/user",
            "http://www.provider.example/user",
            "http://www.provider.example/user",
        ),
        (
            "http://provider.example/user",
            "https://provider.example/user",
            "https://provider.example/user",
        ),
    ],
)
def test_request_follows_redirect_keeping_transport_security(
    url: str, location: str, target: str
) -> None:
    responses.add(responses.GET, url, status=302, headers={"Location": location})
    responses.add(responses.GET, target, json={"id": 1})

    response = get_backend({}).request(url)

    assert response.json() == {"id": 1}
    assert response.url == target


@pytest.fixture
def netrc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "netrc"
    path.write_text("machine provider.example login machine password secret\n")
    path.chmod(0o600)
    monkeypatch.setenv("NETRC", str(path))


@responses.activate
@pytest.mark.usefixtures("netrc")
def test_request_keeps_authorization_header_despite_netrc() -> None:
    responses.get("https://provider.example/user", json={})
    get_backend({}).request(
        "https://provider.example/user", headers={"Authorization": "Bearer token"}
    )
    assert responses.calls[0].request.headers["Authorization"] == "Bearer token"


@responses.activate
@pytest.mark.usefixtures("netrc")
def test_request_keeps_authorization_header_on_redirect_despite_netrc() -> None:
    responses.get(
        "https://provider.example/user",
        status=302,
        headers={"Location": "https://provider.example/users/1"},
    )
    responses.get("https://provider.example/users/1", json={})
    get_backend({}).request(
        "https://provider.example/user", headers={"Authorization": "Bearer token"}
    )
    assert responses.calls[1].request.headers["Authorization"] == "Bearer token"
