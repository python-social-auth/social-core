from __future__ import annotations

from typing import TYPE_CHECKING, Any, Never

from .exceptions import AuthConfigurationError

if TYPE_CHECKING:
    from .strategy import BaseStrategy


class Registry:
    def __init__(self) -> None:
        self._default_strategy: BaseStrategy[Any] | None = None

    def reset(self) -> None:
        self._default_strategy = None

    @property
    def default_strategy(self) -> BaseStrategy[Never]:
        if self._default_strategy is None:
            raise AuthConfigurationError(
                code="missing_setting", parameter="default_strategy"
            )
        return self._default_strategy

    @default_strategy.setter
    def default_strategy(self, strategy: BaseStrategy[Any]) -> None:
        self._default_strategy = strategy


REGISTRY = Registry()
