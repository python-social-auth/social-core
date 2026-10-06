from __future__ import annotations

import json
import unittest
from types import MappingProxyType
from unittest.mock import patch

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthPolicyError
from social_core.pipeline.utils import partial_load, partial_prepare
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME, partial_pipeline_result

from .models import TestPartial, TestStorage
from .strategy import Redirect, TestStrategy


class PipelineRequestDataTest(unittest.TestCase):
    def setUp(self) -> None:
        TestPartial.reset_cache()
        self.strategy = TestStrategy(TestStorage)
        self.backend = BaseAuth(self.strategy)
        self.strategy.set_request_data({"field": "current"}, self.backend)

    def test_nested_context_and_empty_data(self) -> None:
        with self.strategy.pipeline_request_data({"field": "outer"}):
            self.assertEqual(self.strategy.request_data(), {"field": "outer"})
            self.assertEqual(
                self.strategy.request_data(merge=False), {"field": "outer"}
            )
            self.assertEqual(self.strategy.get_request_data(), {"field": "current"})
            with self.strategy.pipeline_request_data({}):
                self.assertEqual(self.strategy.request_data(), {})
            self.assertEqual(self.strategy.request_data(), {"field": "outer"})
        self.assertEqual(self.strategy.request_data(), {"field": "current"})

    def test_context_restored_on_exception(self) -> None:
        with (
            self.assertRaises(ValueError),
            self.strategy.pipeline_request_data({"field": "saved"}),
            patch.object(self.backend, "pipeline", side_effect=ValueError),
        ):
            self.backend.pipeline([])
        self.assertEqual(self.strategy.request_data(), {"field": "current"})

    def test_context_accepts_read_only_mapping(self) -> None:
        with self.strategy.pipeline_request_data(MappingProxyType({"field": "saved"})):
            self.strategy.request_data().clear()
            self.assertEqual(self.strategy.request_data(), {})
        self.assertEqual(self.strategy.request_data(), {"field": "current"})

    def test_context_flattens_multivalue_data(self) -> None:
        class MultiValueDict(dict):
            def dict(self):
                return {key: values[-1] for key, values in self.items()}

        with self.strategy.pipeline_request_data(
            MultiValueDict({"verification_code": ["old", "saved"]})
        ):
            self.assertEqual(
                self.strategy.request_data(), {"verification_code": "saved"}
            )

    def test_partial_snapshot_is_separate_from_kwargs(self) -> None:
        with self.strategy.pipeline_request_data({"field": "saved"}):
            partial = partial_prepare(self.strategy, self.backend, 0, request=object())
        self.assertEqual(partial.request_data, {"field": "saved"})
        self.assertNotIn("request", partial.kwargs)

    def test_legacy_partial_loaded_without_request_kwarg(self) -> None:
        partial = TestPartial.prepare(
            self.backend.name,
            0,
            {"kwargs": {"request": {"field": "legacy"}, "response": {}}, "args": []},
        )
        partial.save()
        loaded = partial_load(self.strategy, partial.token)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.request_data, {"field": "legacy"})
        self.assertNotIn("request", loaded.kwargs)

    def test_encoded_partial_request_data(self) -> None:
        for as_bytes in (False, True):
            for legacy in (False, True):
                with self.subTest(as_bytes=as_bytes, legacy=legacy):

                    def encode(value, as_bytes=as_bytes):
                        if isinstance(value, dict):
                            encoded = json.dumps(value)
                            return encoded.encode() if as_bytes else encoded
                        return value

                    def decode(value):
                        if isinstance(value, (str, bytes)):
                            return json.loads(value)
                        return value

                    with (
                        patch.object(
                            self.strategy, "to_session_value", side_effect=encode
                        ),
                        patch.object(
                            self.strategy, "from_session_value", side_effect=decode
                        ),
                    ):
                        with self.strategy.pipeline_request_data(
                            {"verification_code": "saved"}
                        ):
                            partial = partial_prepare(self.strategy, self.backend, 0)
                        self.assertIsInstance(
                            partial.data["request_data"], (str, bytes)
                        )
                        if legacy:
                            partial.kwargs["request"] = partial.data.pop("request_data")
                        partial.save()
                        loaded = partial_load(self.strategy, partial.token)
                        assert loaded is not None
                        self.assertEqual(
                            loaded.request_data, {"verification_code": "saved"}
                        )
                        self.assertNotIn("request", loaded.kwargs)
                        with patch.object(
                            self.backend,
                            "pipeline",
                            side_effect=lambda *_args, **_kwargs: (
                                self.strategy.request_data()
                            ),
                        ):
                            self.assertEqual(
                                self.backend.continue_pipeline(loaded),
                                {"verification_code": "saved"},
                            )

    def test_decoded_snapshot_must_be_a_mapping(self) -> None:
        for decoded in (None, ["invalid"], "invalid"):
            with self.subTest(decoded=decoded):
                partial = partial_prepare(self.strategy, self.backend, 0)
                partial.save()
                with patch.object(
                    self.strategy, "from_session_value", return_value=decoded
                ):
                    loaded = partial_load(self.strategy, partial.token)
                assert loaded is not None
                self.assertIsNone(loaded.request_data)

    def test_authentication_resume_scopes_strategy_and_backend_data(self) -> None:
        partial = TestPartial.prepare(
            self.backend.name,
            0,
            {
                "request_data": {"field": "saved"},
                "kwargs": {"response": {}},
                "args": [],
            },
        )

        def pipeline(*args, **kwargs):
            self.assertEqual(self.strategy.request_data(), {"field": "saved"})
            self.assertEqual(self.backend.data, {"field": "saved"})
            self.assertNotIn("request", kwargs)
            return self.strategy.redirect("/next")

        with patch.object(self.backend, "pipeline", side_effect=pipeline):
            response = self.backend.continue_pipeline(partial)
            self.assertIsInstance(response, Redirect)
            assert isinstance(response, Redirect)
            self.assertEqual(response.url, "/next")
        self.assertEqual(self.strategy.request_data(), {"field": "current"})
        self.assertEqual(self.backend.data, {"field": "current"})

    def test_authentication_resume_restores_backend_data_on_exception(self) -> None:
        partial = partial_prepare(self.strategy, self.backend, 0, response={})
        partial.request_data = {"field": "saved"}
        with (
            patch.object(self.backend, "pipeline", side_effect=ValueError),
            self.assertRaises(ValueError),
        ):
            self.backend.continue_pipeline(partial)
        self.assertEqual(self.backend.data, {"field": "current"})
        self.assertEqual(self.strategy.request_data(), {"field": "current"})

    def test_disconnect_resume_scopes_data_and_continues_at_saved_step(self) -> None:
        partial = TestPartial.prepare(
            self.backend.name,
            2,
            {
                "request_data": {"field": "saved"},
                "pipeline_type": "disconnect",
                "kwargs": {},
                "args": [],
            },
        )

        def run_pipeline(pipeline, pipeline_index, **kwargs):
            self.assertEqual(pipeline_index, 2)
            self.assertEqual(self.backend.data, {"field": "saved"})
            self.assertEqual(self.strategy.request_data(), {"field": "saved"})
            return {"done": True}

        with patch.object(self.backend, "run_pipeline", side_effect=run_pipeline):
            self.assertEqual(
                self.backend.continue_disconnect_pipeline(partial), {"done": True}
            )
        self.assertEqual(self.backend.data, {"field": "current"})
        self.assertEqual(self.strategy.request_data(), {"field": "current"})

    def test_continuations_reject_other_pipeline_types(self) -> None:
        partial = partial_prepare(self.strategy, self.backend, 1)
        with (
            patch.object(self.backend, "run_pipeline") as run_pipeline,
            self.assertRaises(AuthPolicyError),
        ):
            self.backend.continue_disconnect_pipeline(partial)
        run_pipeline.assert_not_called()
        partial.data["pipeline_type"] = "disconnect"
        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthPolicyError),
        ):
            self.backend.continue_pipeline(partial)
        authenticate.assert_not_called()

    def test_owned_partial_uses_new_request_data(self) -> None:
        partial = partial_prepare(self.strategy, self.backend, 0, response={})
        partial.request_data = {"field": "old"}
        partial.save()
        self.strategy.session_set(PARTIAL_TOKEN_SESSION_NAME, partial.token)
        result = partial_pipeline_result(self.backend)
        self.assertIsNotNone(result.partial)
        assert result.partial is not None
        self.assertEqual(result.partial.request_data, {"field": "current"})
        self.assertNotIn("request", result.partial.kwargs)

    def test_pipeline_does_not_inject_request(self) -> None:
        out = self.backend.run_pipeline([], request={"field": "old"})
        assert isinstance(out, dict)
        self.assertNotIn("request", out)

    def test_sequential_resumes_do_not_leak_data(self) -> None:
        with patch.object(
            self.backend,
            "pipeline",
            side_effect=lambda *_args, **_kwargs: self.strategy.request_data().copy(),
        ):
            for value in ("first", "second"):
                partial = partial_prepare(self.strategy, self.backend, 0, response={})
                partial.request_data = {"field": value}
                self.assertEqual(
                    self.backend.continue_pipeline(partial), {"field": value}
                )
        self.assertEqual(self.strategy.request_data(), {"field": "current"})
