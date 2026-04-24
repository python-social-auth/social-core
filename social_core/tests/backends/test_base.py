from __future__ import annotations

from social_core.backends.base import BaseAuth
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy


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
