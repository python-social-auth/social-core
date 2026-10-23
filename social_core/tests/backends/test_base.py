from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthConfigurationError
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy

if TYPE_CHECKING:
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
