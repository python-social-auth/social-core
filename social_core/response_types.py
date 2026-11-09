from typing import Protocol


class HttpResponseProtocol(Protocol):
    """Deprecated URL-bearing response protocol kept for compatibility.

    Strategies are generic in their actual response type; new integrations
    should annotate that concrete response type instead of using this protocol.
    """

    @property
    def url(self) -> str: ...
