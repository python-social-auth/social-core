"""Static coverage for strategy response types."""

from dataclasses import dataclass
from typing import Any

from social_core.pipeline.partial import partial
from social_core.strategy import BaseStrategy


@dataclass
class HtmlResponse:
    content: str


class HtmlStrategy(BaseStrategy[HtmlResponse]):
    def html(self, content: str) -> HtmlResponse:
        return HtmlResponse(content)


def html_pipeline_step(**kwargs: Any) -> HtmlResponse:
    return HtmlResponse("rendered page")


partial_html_step = partial(html_pipeline_step)
