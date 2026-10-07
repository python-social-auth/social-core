import copy
import json
from typing import Any
from unittest import TestCase
from unittest.mock import Mock, patch

from openid.association import Association
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.yadis.manager import Discovery, YadisServiceManager

from social_core.backends.open_id import OpenIdAuth
from social_core.exceptions import AuthSessionError
from social_core.store import InvalidOpenIdSession, OpenIdSessionWrapper, OpenIdStore
from social_core.tests.models import TestAssociation, TestStorage
from social_core.tests.strategy import TestStrategy

ENDPOINT_KEY = OpenIdSessionWrapper.endpoint_key
MANAGER_KEY = OpenIdSessionWrapper.manager_key
IDENTITY = "https://example.com/élise"


def make_endpoint(url=IDENTITY) -> OpenIDServiceEndpoint:
    endpoint = OpenIDServiceEndpoint()
    fields: dict[str, Any] = {
        "claimed_id": url,
        "server_url": "https://provider.example.com/openid",
        "type_uris": ["http://specs.openid.net/auth/2.0/signon"],
        "local_id": "https://provider.example.com/élise",
        "canonicalID": "=élise",
        "used_yadis": True,
        "display_identifier": "Élise",
    }
    for name, value in fields.items():
        setattr(endpoint, name, value)
    return endpoint


def endpoint_fields(endpoint) -> dict[str, Any]:
    return {
        name: getattr(endpoint, name)
        for name in (
            "claimed_id",
            "server_url",
            "type_uris",
            "local_id",
            "canonicalID",
            "used_yadis",
            "display_identifier",
        )
    }


class OpenIdSessionTests(TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.session = self.strategy.openid_session_dict("openid")

    def reload_session(self):
        strategy = self.strategy.new_request()
        return strategy.openid_session_dict("openid")

    def test_endpoint_json_round_trip(self) -> None:
        for endpoint in (OpenIDServiceEndpoint(), make_endpoint()):
            with self.subTest(endpoint=endpoint_fields(endpoint)):
                self.session[ENDPOINT_KEY] = endpoint
                restored = self.reload_session()[ENDPOINT_KEY]
                self.assertEqual(endpoint_fields(restored), endpoint_fields(endpoint))
                # Mutating the reconstructed object cannot change saved state.
                restored.type_uris.append("another-type")
                self.assertEqual(
                    endpoint_fields(self.session[ENDPOINT_KEY]),
                    endpoint_fields(endpoint),
                )
        endpoint = self.session.get(ENDPOINT_KEY)
        assert endpoint is not None
        self.assertEqual(endpoint.claimed_id, IDENTITY)

    def test_mapping_views_decode_values_and_snapshot_encodes_them(self) -> None:
        endpoint = make_endpoint()
        manager = YadisServiceManager(IDENTITY, IDENTITY, [endpoint], MANAGER_KEY)
        self.session.update(
            {ENDPOINT_KEY: endpoint, MANAGER_KEY: manager}, ordinary="value"
        )
        self.assertEqual(len(self.session), 3)
        self.assertEqual(
            list(self.session.keys()), [ENDPOINT_KEY, MANAGER_KEY, "ordinary"]
        )
        for mapping in (dict(self.session), dict(self.session.items())):
            self.assertEqual(
                endpoint_fields(mapping[ENDPOINT_KEY]), endpoint_fields(endpoint)
            )
            self.assertIsInstance(mapping[MANAGER_KEY], YadisServiceManager)
            self.assertEqual(mapping["ordinary"], "value")
        values = list(self.session.values())
        self.assertEqual(endpoint_fields(values[0]), endpoint_fields(endpoint))
        self.assertIsInstance(values[1], YadisServiceManager)
        self.assertEqual(values[2], "value")
        snapshot = self.session.snapshot()
        self.assertEqual(json.loads(json.dumps(snapshot)), snapshot)
        self.assertEqual(snapshot, self.strategy.session_get("openid"))
        restored = OpenIdSessionWrapper(snapshot)
        self.assertEqual(
            endpoint_fields(restored[ENDPOINT_KEY]), endpoint_fields(endpoint)
        )
        self.assertEqual(len(restored[MANAGER_KEY]), 1)

    def test_discovery_fallback_and_cleanup(self) -> None:
        first, second = make_endpoint(), make_endpoint("https://example.com/second")
        discovery = Discovery(self.session, IDENTITY, "_openid_consumer_")
        discover = Mock(return_value=(IDENTITY, [first, second]))
        self.assertEqual(
            endpoint_fields(discovery.getNextService(discover)), endpoint_fields(first)
        )
        restored = self.reload_session()
        manager = restored[MANAGER_KEY]
        self.assertEqual(endpoint_fields(manager.current()), endpoint_fields(first))
        self.assertEqual(
            [endpoint_fields(item) for item in manager.services],
            [endpoint_fields(second)],
        )
        discovery = Discovery(restored, IDENTITY, "_openid_consumer_")
        self.assertEqual(
            endpoint_fields(discovery.getNextService(discover)), endpoint_fields(second)
        )
        manager = discovery.getManager()
        assert manager is not None
        self.assertEqual(len(manager), 0)
        discover.assert_called_once_with(IDENTITY)
        self.assertEqual(endpoint_fields(discovery.cleanup()), endpoint_fields(second))
        self.assertNotIn(MANAGER_KEY, restored)

    def test_unstarted_and_exhausted_manager(self) -> None:
        manager = YadisServiceManager(IDENTITY, None, [], MANAGER_KEY)
        self.session[MANAGER_KEY] = manager
        restored = self.reload_session()[MANAGER_KEY]
        self.assertFalse(restored.started())
        self.assertEqual(len(restored), 0)
        self.assertIsNone(restored.yadis_url)
        self.assertIsNone(restored.current())

    def test_mutations_persist_encoded_state(self) -> None:
        with patch.object(
            self.strategy, "session_set", wraps=self.strategy.session_set
        ) as save:
            endpoint = make_endpoint()
            self.session.update({ENDPOINT_KEY: endpoint}, ordinary="value")
            self.assertEqual(self.reload_session()["ordinary"], "value")
            self.assertEqual(
                endpoint_fields(self.reload_session()[ENDPOINT_KEY]),
                endpoint_fields(endpoint),
            )
            other = OpenIdSessionWrapper()
            other.update(self.session)
            self.assertEqual(
                endpoint_fields(other[ENDPOINT_KEY]), endpoint_fields(endpoint)
            )
            save.reset_mock()
            self.assertEqual(self.session.setdefault("ordinary", "unused"), "value")
            self.session.get(ENDPOINT_KEY)
            save.assert_not_called()
            self.session.setdefault("new", "default")
            self.assertEqual(self.reload_session()["new"], "default")
            self.session |= {"merged": True}
            self.assertTrue(self.reload_session()["merged"])
            self.assertEqual(self.session.popitem(), ("merged", True))
            self.assertNotIn("merged", self.reload_session())
            self.assertEqual(
                endpoint_fields(self.session.pop(ENDPOINT_KEY)),
                endpoint_fields(endpoint),
            )
            self.assertNotIn(ENDPOINT_KEY, self.reload_session())
            del self.session["ordinary"]
            self.assertNotIn("ordinary", self.reload_session())
            self.session.clear()
            self.assertEqual(self.strategy.session_get("openid"), {})
            self.assertIsNone(self.session.pop("absent", None))
            with self.assertRaises(KeyError):
                self.session.pop("absent")
            with self.assertRaises(KeyError):
                self.session.popitem()

    def test_ordinary_and_unrelated_state_preserved(self) -> None:
        self.strategy.session_set("other", {"keep": True})
        self.session["ordinary"] = {"list": [None, True, "text"]}
        restored = self.strategy.openid_session_dict("openid")
        self.assertEqual(restored["ordinary"], {"list": [None, True, "text"]})
        self.assertEqual(self.strategy.session_get("other"), {"keep": True})

    def test_invalid_assignments_preserve_saved_state(self) -> None:
        endpoint = make_endpoint()
        manager = YadisServiceManager(IDENTITY, IDENTITY, [endpoint], MANAGER_KEY)
        self.session.update({ENDPOINT_KEY: endpoint, MANAGER_KEY: manager})
        saved = copy.deepcopy(self.strategy.session_get("openid"))
        invalid: list[Any] = [None, {}, b"old pickle", object()]
        with patch.object(self.strategy, "session_set") as save:
            for key, wrong_object in ((ENDPOINT_KEY, manager), (MANAGER_KEY, endpoint)):
                for value in [*invalid, wrong_object]:
                    with (
                        self.subTest(key=key, value=value),
                        self.assertRaises(InvalidOpenIdSession),
                    ):
                        self.session[key] = value
            save.assert_not_called()
        self.assertEqual(self.session.snapshot(), saved)
        self.assertEqual(self.strategy.session_get("openid"), saved)

    def test_reject_invalid_state(self) -> None:
        self.session[ENDPOINT_KEY] = make_endpoint()
        self.session[MANAGER_KEY] = YadisServiceManager(
            IDENTITY, IDENTITY, [make_endpoint()], MANAGER_KEY
        )
        valid = self.session.snapshot()
        invalid: list[Any] = [None, [], "old state", b"old pickle", {}]
        for key in (ENDPOINT_KEY, MANAGER_KEY):
            for value in invalid:
                state = copy.deepcopy(valid)
                state[key] = value
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(InvalidOpenIdSession),
                ):
                    OpenIdSessionWrapper(state)
            for version in (0, 2, True, 1.0, "1"):
                state = copy.deepcopy(valid)
                state[key]["version"] = version
                with (
                    self.subTest(key=key, version=version),
                    self.assertRaises(InvalidOpenIdSession),
                ):
                    OpenIdSessionWrapper(state)
            for field in valid[key]["data"]:
                state = copy.deepcopy(valid)
                del state[key]["data"][field]
                with (
                    self.subTest(key=key, missing=field),
                    self.assertRaises(InvalidOpenIdSession),
                ):
                    OpenIdSessionWrapper(state)
            state = copy.deepcopy(valid)
            state[key]["data"]["__class__"] = "os.system"
            with self.assertRaises(InvalidOpenIdSession):
                OpenIdSessionWrapper(state)
        bad_fields: dict[str, dict[str, Any]] = {
            ENDPOINT_KEY: {"claimed_id": 3, "type_uris": [False], "used_yadis": 1},
            MANAGER_KEY: {
                "starting_url": None,
                "yadis_url": 3,
                "session_key": "different",
                "services": [b"pickle"],
                "_current": {},
            },
        }
        for key, fields in bad_fields.items():
            for field, value in fields.items():
                state = copy.deepcopy(valid)
                state[key]["data"][field] = value
                with (
                    self.subTest(key=key, field=field),
                    self.assertRaises(InvalidOpenIdSession),
                ):
                    OpenIdSessionWrapper(state)
        invalid_sessions: list[Any] = [None, [], "invalid"]
        for invalid_session in invalid_sessions:
            with self.assertRaises(InvalidOpenIdSession):
                OpenIdSessionWrapper(invalid_session)

    def test_callback_rejects_old_state_without_unpickling(self) -> None:
        invalid_states = [
            {key: value}
            for key in (ENDPOINT_KEY, MANAGER_KEY)
            for value in (b"old pickle", {"version": 2, "data": {}})
        ]
        for state in invalid_states:
            self.strategy.session_set("openid", state)
            self.strategy.session_set("other", "preserved")
            backend = OpenIdAuth(
                self.strategy, redirect_uri="https://example.com/callback"
            )
            with (
                patch("pickle.loads", side_effect=AssertionError("must not unpickle")),
                self.assertRaises(AuthSessionError) as caught,
            ):
                backend.auth_complete()
            self.assertEqual(caught.exception.code, "session_context_missing")
            self.assertEqual(caught.exception.stage, "callback")
            self.assertEqual(self.strategy.session_get("openid"), {})
            self.assertEqual(self.strategy.session_get("other"), "preserved")

    def test_new_login_discards_stale_state(self) -> None:
        self.strategy.session_set("openid", {MANAGER_KEY: b"old pickle"})
        backend = OpenIdAuth(self.strategy, redirect_uri="https://example.com/callback")
        self.strategy.set_request_data({"openid_identifier": IDENTITY}, backend)
        endpoint = make_endpoint()
        request = Mock(endpoint=endpoint)
        with (
            patch(
                "openid.consumer.consumer.Consumer._discover",
                return_value=(IDENTITY, [endpoint]),
            ),
            patch(
                "openid.consumer.consumer.GenericConsumer.begin", return_value=request
            ),
            patch("pickle.loads", side_effect=AssertionError("must not unpickle")),
        ):
            self.assertIs(backend.openid_request(), request)
        self.assertEqual(
            endpoint_fields(self.reload_session()[ENDPOINT_KEY]),
            endpoint_fields(endpoint),
        )

    def test_existing_provider_association_is_reused(self) -> None:
        TestAssociation.reset_cache()
        self.addCleanup(TestAssociation.reset_cache)
        association = Association.fromExpiresIn(600, "handle", b"secret", "HMAC-SHA1")
        store = OpenIdStore(self.strategy)
        store.storeAssociation(make_endpoint().server_url, association)
        self.session[ENDPOINT_KEY] = make_endpoint()
        self.reload_session()
        backend = OpenIdAuth(self.strategy.new_request())
        with patch(
            "openid.consumer.consumer.fetchers.fetch",
            side_effect=AssertionError("must reuse stored association"),
        ):
            request = backend.consumer().beginWithoutDiscovery(make_endpoint())
        self.assertEqual(request.assoc.serialize(), association.serialize())
