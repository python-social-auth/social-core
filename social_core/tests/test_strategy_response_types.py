"""Static coverage for strategy response types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, assert_type

from social_core.actions import do_auth, do_complete
from social_core.pipeline.partial import partial
from social_core.storage import UserProtocol
from social_core.strategy import BaseStrategy
from social_core.utils import PartialPipelineResult, partial_pipeline_result

if TYPE_CHECKING:
    from social_core.backends.base import BaseAuth


@dataclass
class HtmlResponse:
    content: str


class HtmlStrategy(BaseStrategy[HtmlResponse]):
    def html(self, content: str) -> HtmlResponse:
        return HtmlResponse(content)


def html_pipeline_step(**kwargs: Any) -> HtmlResponse:
    return HtmlResponse("rendered page")


partial_html_step = partial(html_pipeline_step)


def response_free_pipeline_step(**kwargs: Any) -> None:
    return None


partial_response_free_step = partial(response_free_pipeline_step)


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
    assert_type(partial_html_step(), dict[str, Any] | HtmlResponse)
