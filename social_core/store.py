from __future__ import annotations

import time
from collections.abc import MutableMapping
from typing import TYPE_CHECKING, Any

from openid.consumer.discover import OpenIDServiceEndpoint
from openid.store.interface import OpenIDStore as BaseOpenIDStore
from openid.store.nonce import SKEW
from openid.yadis.manager import YadisServiceManager

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


class OpenIdStore(BaseOpenIDStore):
    """Storage class"""

    def __init__(self, strategy) -> None:
        """Init method"""
        super().__init__()
        self.strategy = strategy
        self.storage = strategy.storage
        self.assoc = self.storage.association
        self.nonce = self.storage.nonce
        self.max_nonce_age = 6 * 60 * 60  # Six hours

    def storeAssociation(self, server_url, association) -> None:
        """Store new association if it does not exist"""
        self.assoc.store(server_url, association)

    def removeAssociation(self, server_url, handle) -> None:
        """Remove association"""
        associations_ids = list(dict(self.assoc.oids(server_url, handle)).keys())
        if associations_ids:
            self.assoc.remove(associations_ids)

    def expiresIn(self, assoc):
        if hasattr(assoc, "getExpiresIn"):
            return assoc.getExpiresIn()
        # python3-openid 3.0.2
        return assoc.expiresIn

    def getAssociation(self, server_url, handle=None):
        """Return stored association"""
        associations, expired = [], []
        for assoc_id, association in self.assoc.oids(server_url, handle):
            expires = self.expiresIn(association)
            if expires > 0:
                associations.append(association)
            elif expires == 0:
                expired.append(assoc_id)

        if expired:  # clear expired associations
            self.assoc.remove(expired)

        if associations:  # return most recet association
            return associations[0]
        return None

    def useNonce(self, server_url, timestamp, salt):
        """Generate one use number and return *if* it was created"""
        if abs(timestamp - time.time()) > SKEW:
            return False
        return self.nonce.use(server_url, timestamp, salt)


class InvalidOpenIdSession(ValueError):
    """OpenID session state cannot be safely reconstructed."""


_ENDPOINT_FIELDS = {
    "claimed_id",
    "server_url",
    "type_uris",
    "local_id",
    "canonicalID",
    "used_yadis",
    "display_identifier",
}
_MANAGER_FIELDS = {"starting_url", "yadis_url", "session_key", "services", "_current"}
_MISSING = object()


def _session_data(value, fields):
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "data"}
        or not isinstance(value["version"], int)
        or isinstance(value["version"], bool)
        or value["version"] != 1
    ):
        raise InvalidOpenIdSession("Invalid OpenID session format")
    if not isinstance(value["data"], dict) or set(value["data"]) != fields:
        raise InvalidOpenIdSession("Invalid OpenID session fields")
    return value["data"]


def _decode_endpoint(value):
    data = _session_data(value, _ENDPOINT_FIELDS)
    if (
        any(
            data[name] is not None and not isinstance(data[name], str)
            for name in _ENDPOINT_FIELDS - {"type_uris", "used_yadis"}
        )
        or not isinstance(data["type_uris"], list)
        or not all(isinstance(uri, str) for uri in data["type_uris"])
        or not isinstance(data["used_yadis"], bool)
    ):
        raise InvalidOpenIdSession("Invalid OpenID endpoint fields")
    endpoint = OpenIDServiceEndpoint()
    for name in _ENDPOINT_FIELDS:
        setattr(
            endpoint, name, data[name].copy() if name == "type_uris" else data[name]
        )
    return endpoint


def _encode_endpoint(endpoint):
    if not isinstance(endpoint, OpenIDServiceEndpoint):
        raise InvalidOpenIdSession("Expected an OpenID endpoint")
    value: dict[str, Any] = {
        "version": 1,
        "data": {name: getattr(endpoint, name) for name in _ENDPOINT_FIELDS},
    }
    _decode_endpoint(value)
    value["data"]["type_uris"] = value["data"]["type_uris"].copy()
    return value


class OpenIdSessionWrapper(MutableMapping[str, Any]):
    """Expose OpenID objects while storing only JSON-compatible state."""

    manager_key = "_yadis_services__openid_consumer_"
    endpoint_key = "_openid_consumer_last_token"

    def __init__(
        self, values=_MISSING, *, on_change: Callable[[dict], None] | None = None
    ) -> None:
        if values is _MISSING:
            values = {}
        if not isinstance(values, dict):
            raise InvalidOpenIdSession("Expected an OpenID session dictionary")
        self._data: dict[str, Any] = values.copy()
        self._on_change = on_change
        for name in (self.manager_key, self.endpoint_key):
            if name in self._data:
                self._decode(name, self._data[name])

    def _decode(self, name, value):
        if name == self.endpoint_key:
            return _decode_endpoint(value)
        if name != self.manager_key:
            return value
        data = _session_data(value, _MANAGER_FIELDS)
        if (
            not isinstance(data["starting_url"], str)
            or (
                data["yadis_url"] is not None and not isinstance(data["yadis_url"], str)
            )
            or data["session_key"] != self.manager_key
            or not isinstance(data["services"], list)
        ):
            raise InvalidOpenIdSession("Invalid OpenID discovery fields")
        services = [_decode_endpoint(service) for service in data["services"]]
        current = (
            None if data["_current"] is None else _decode_endpoint(data["_current"])
        )
        if current is not None:
            services.insert(0, current)
        manager = YadisServiceManager(
            data["starting_url"], data["yadis_url"], services, data["session_key"]
        )
        # Advancing restores the current endpoint without leaving it untried.
        if current is not None:
            next(manager)
        return manager

    def _encode(self, name, value):
        if name == self.endpoint_key:
            return _encode_endpoint(value)
        if name != self.manager_key:
            return value
        if not isinstance(value, YadisServiceManager):
            raise InvalidOpenIdSession("Expected an OpenID discovery manager")
        encoded = {
            "version": 1,
            "data": {
                "starting_url": value.starting_url,
                "yadis_url": value.yadis_url,
                "session_key": value.session_key,
                "services": [_encode_endpoint(service) for service in value.services],
                "_current": None
                if value.current() is None
                else _encode_endpoint(value.current()),
            },
        }
        self._decode(name, encoded)
        return encoded

    def _persist(self) -> None:
        if self._on_change is not None:
            self._on_change(self.snapshot())

    def snapshot(self) -> dict[str, Any]:
        """Return encoded session data suitable for framework serialization."""
        return self._data.copy()

    def __getitem__(self, name: str) -> Any:
        return self._decode(name, self._data[name])

    def __setitem__(self, name: str, value: Any) -> None:
        self._data[name] = self._encode(name, value)
        self._persist()

    def __delitem__(self, name: str) -> None:
        del self._data[name]
        self._persist()

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def popitem(self):
        # Retain the dictionary interface's last-in-first-out behavior.
        if not self:
            raise KeyError("popitem(): dictionary is empty")
        name = next(reversed(self._data))
        return name, self.pop(name)

    def __ior__(self, values, /):
        self.update(values)
        return self
