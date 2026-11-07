"""Static coverage for strategy response types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Never, assert_type

from social_core.actions import do_auth, do_complete
from social_core.backends.base import BaseAuth
from social_core.backends.github import GithubOAuth2
from social_core.pipeline.partial import partial, partial_step
from social_core.registry import REGISTRY
from social_core.storage import UserMixin, UserProtocol
from social_core.strategy import BaseStrategy, HttpResponseProtocol
from social_core.utils import PartialPipelineResult, partial_pipeline_result


@dataclass
class HtmlResponse:
    content: str


class HtmlStrategy(BaseStrategy[HtmlResponse]):
    def get_setting(self, name: str) -> Any:
        return None

    def get_request_data(self, merge: bool = True) -> dict[str, Any]:
        return {}

    def build_absolute_uri(self, path: str | None = None) -> str:
        return path or "https://example.com/"

    def redirect(self, url: str) -> HtmlResponse:
        return HtmlResponse(url)

    def html(self, content: str) -> HtmlResponse:
        return HtmlResponse(content)


class HtmlBackend(BaseAuth[HtmlResponse]):
    def auth_url(self) -> str:
        return "/provider-login"


def html_pipeline_step(**kwargs: Any) -> HtmlResponse:  # pragma: no cover
    return HtmlResponse("rendered page")


partial_html_step = partial(html_pipeline_step)


def response_free_pipeline_step(**kwargs: Any) -> None:  # pragma: no cover
    return None


partial_response_free_step = partial(response_free_pipeline_step)
partial_step_response_free_step = partial_step(save_to_session=False)(
    response_free_pipeline_step
)


def test_backend_returns_response_without_redirect_url(monkeypatch) -> None:
    strategy = HtmlStrategy()
    response = HtmlBackend(strategy).start()

    def fake_auth_url(_backend: GithubOAuth2[HtmlResponse]) -> str:
        return "/authorize"

    monkeypatch.setattr(GithubOAuth2, "auth_url", fake_auth_url)
    concrete_response = GithubOAuth2(strategy).start()
    html = strategy.html("rendered")

    assert response.content == "/provider-login"
    assert isinstance(concrete_response, HtmlResponse)
    assert not hasattr(response, "url")
    assert not hasattr(concrete_response, "url")
    assert html.content == "rendered"
    assert not hasattr(html, "url")


# These functions are inputs to static type checkers and intentionally aren't
# executed as runtime tests.
def verify_response_type_flow(
    backend: BaseAuth[HtmlResponse],
) -> None:  # pragma: no cover
    assert_type(backend.start(), HtmlResponse)
    assert_type(backend.strategy.redirect("/"), HtmlResponse)
    assert_type(do_auth(backend), HtmlResponse)
    assert_type(do_complete(backend, login=print), HtmlResponse)
    assert_type(
        backend.authenticate(),
        UserProtocol | HtmlResponse | None,
    )
    assert_type(
        backend.strategy.authenticate(backend),
        UserProtocol | HtmlResponse | None,
    )
    assert_type(
        backend.run_pipeline([]),
        dict[str, Any] | HtmlResponse,
    )
    assert_type(
        backend.complete(),
        UserProtocol | HtmlResponse | None,
    )
    partial_result: PartialPipelineResult[HtmlResponse] = partial_pipeline_result(
        backend
    )
    assert_type(partial_result.response, HtmlResponse | None)
    assert_type(
        partial_response_free_step(backend.strategy, backend, 0), dict[str, Any]
    )
    assert_type(
        partial_step_response_free_step(backend.strategy, backend, 0),
        dict[str, Any],
    )
    assert_type(
        partial_html_step(backend.strategy, backend, 0), dict[str, Any] | HtmlResponse
    )


def verify_concrete_backend_response_type(
    strategy: BaseStrategy[HttpResponseProtocol],
) -> None:  # pragma: no cover
    backend = GithubOAuth2(strategy)
    assert_type(backend.strategy, BaseStrategy[HttpResponseProtocol])
    assert_type(backend.start(), HttpResponseProtocol)
    assert_type(do_auth(backend), HttpResponseProtocol)
    assert_type(backend.strategy.get_backend("github"), BaseAuth[HttpResponseProtocol])


def verify_backend_constructor_preserves_response_type(
    strategy: HtmlStrategy,
) -> None:  # pragma: no cover
    backend = BaseAuth(strategy)
    assert_type(backend, BaseAuth[HtmlResponse])
    assert_type(backend.strategy, BaseStrategy[HtmlResponse])


def verify_registry_default_strategy_is_response_free() -> None:  # pragma: no cover
    assert_type(REGISTRY.default_strategy, BaseStrategy[Never])


def verify_backend_factory_preserves_response_type(
    strategy: HtmlStrategy,
) -> None:  # pragma: no cover
    backend = strategy.get_backend("github")
    assert_type(backend, BaseAuth[HtmlResponse])
    assert_type(backend.start(), HtmlResponse)
    assert_type(do_auth(backend), HtmlResponse)


def verify_concrete_html_backend_response_type(
    strategy: HtmlStrategy,
) -> None:  # pragma: no cover
    backend = GithubOAuth2(strategy)
    assert_type(backend, GithubOAuth2[HtmlResponse])
    assert_type(backend.start(), HtmlResponse)


def verify_registry_accepts_any_strategy_response_type(
    strategy: HtmlStrategy,
) -> None:  # pragma: no cover
    REGISTRY.default_strategy = strategy


def verify_user_backend_factory_preserves_response_type(
    user: UserMixin, strategy: HtmlStrategy
) -> None:  # pragma: no cover
    assert_type(user.get_backend(strategy), type[BaseAuth[HtmlResponse]])
    assert_type(user.get_backend_instance(strategy), BaseAuth[HtmlResponse] | None)
