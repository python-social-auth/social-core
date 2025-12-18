from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import DefaultStrategyMissingError

if TYPE_CHECKING:
    from .strategy import BaseStrategy


class Registry:
    def __init__(self) -> None:
        self._default_strategy: BaseStrategy | None = None

    def reset(self) -> None:
        self._default_strategy = None

    @property
    def default_strategy(self) -> BaseStrategy:
        if self._default_strategy is None:
            raise DefaultStrategyMissingError
        return self._default_strategy

    @default_strategy.setter
    def default_strategy(self, strategy: BaseStrategy) -> None:
        self._default_strategy = strategy


REGISTRY = Registry()
