"""Static coverage for strategy response types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, assert_type

from social_core.actions import do_auth, do_complete
from social_core.backends.base import BaseAuth
from social_core.backends.github import GithubOAuth2
from social_core.pipeline.partial import partial, partial_step
from social_core.storage import UserProtocol
from social_core.strategy import BaseStrategy, HttpResponseProtocol
from social_core.utils import PartialPipelineResult, partial_pipeline_result


@dataclass
class HtmlResponse:
    content: str

    @property
    def url(self) -> str:
        return "https://example.com/"


class HtmlStrategy(BaseStrategy[HtmlResponse]):
    def html(self, content: str) -> HtmlResponse:
        return HtmlResponse(content)


def html_pipeline_step(**kwargs: Any) -> HtmlResponse:
    return HtmlResponse("rendered page")


partial_html_step = partial(html_pipeline_step)


def response_free_pipeline_step(**kwargs: Any) -> None:
    return None


partial_response_free_step = partial(response_free_pipeline_step)
partial_step_response_free_step = partial_step(save_to_session=False)(
    response_free_pipeline_step
)


def verify_response_type_flow(backend: BaseAuth[HtmlResponse]) -> None:
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
    assert_type(partial_response_free_step(), dict[str, Any])
    assert_type(partial_step_response_free_step(), dict[str, Any])
    assert_type(partial_html_step(), dict[str, Any] | HtmlResponse)


def verify_concrete_backend_response_type(strategy: HtmlStrategy) -> None:
    backend = GithubOAuth2(strategy)
    assert_type(backend.strategy, BaseStrategy[HttpResponseProtocol])
    assert_type(backend.start(), HttpResponseProtocol)
    assert_type(do_auth(backend), HttpResponseProtocol)

    factory_backend = strategy.get_backend("github")
    assert_type(factory_backend, BaseAuth[HtmlResponse])
    assert_type(factory_backend.start(), HtmlResponse)
