import base64
import unittest
from typing import TYPE_CHECKING, cast
from unittest.mock import Mock, patch

from social_core.backends.base import BaseAuth
from social_core.pipeline.utils import partial_prepare
from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_PENDING_CONFIRMATION_SESSION_NAME,
    PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
    PARTIAL_TOKEN_PENDING_SESSION_NAME,
    PARTIAL_TOKEN_SESSION_NAME,
    build_absolute_uri,
    partial_pipeline_data,
    partial_pipeline_result,
    sanitize_redirect,
    slugify,
    user_is_active,
    user_is_authenticated,
)

from .models import TestPartial, TestStorage
from .strategy import TestStrategy

if TYPE_CHECKING:
    from social_core.storage import PartialMixin, UserProtocol


class SanitizeRedirectTest(unittest.TestCase):
    def test_none_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], None), None)

    def test_empty_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], ""), None)

    def test_dict_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], {}), None)

    def test_invalid_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], {"foo": "bar"}), None)

    def test_wrong_path_redirect(self) -> None:
        self.assertEqual(
            sanitize_redirect(["myapp.com"], "http://notmyapp.com/path/"), None
        )

    def test_invalid_evil_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], "///evil.com"), None)

    def test_invalid_backslash_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], "/\\evil.com"), None)

    def test_invalid_control_character_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], "/path/\n"), None)

    def test_invalid_absolute_url_without_host_redirect(self) -> None:
        for url in [
            "https:///evil.example/path",
            "http:////evil.example/path",
            "http:///evil.example",
            "http:evil.example/path",
            "http:/evil.example/path",
            "https:///myapp.com/path",
        ]:
            self.assertEqual(sanitize_redirect(["myapp.com"], url), None)

    def test_invalid_non_web_scheme_redirect(self) -> None:
        for url in [
            "javascript://myapp.com/%0Aalert(1)",
            "vbscript://myapp.com/msgbox(1)",
            "ftp://myapp.com/path",
            "custom-scheme://myapp.com/path",
        ]:
            self.assertEqual(sanitize_redirect(["myapp.com"], url), None)

    def test_valid_absolute_redirect(self) -> None:
        self.assertEqual(
            sanitize_redirect(["myapp.com"], "http://myapp.com/path/"),
            "http://myapp.com/path/",
        )

    def test_valid_relative_redirect(self) -> None:
        self.assertEqual(sanitize_redirect(["myapp.com"], "/path/"), "/path/")

    def test_multiple_hosts(self) -> None:
        allowed_hosts = ["myapp1.com", "myapp2.com"]
        for host in allowed_hosts:
            url = f"http://{host}/path/"
            self.assertEqual(sanitize_redirect(allowed_hosts, url), url)

    def test_invalid_unicode_nfkc_redirect(self) -> None:
        """URLs with invalid netloc chars under NFKC like \u2100 should return None"""
        self.assertEqual(
            sanitize_redirect(["myapp.com"], "https://evil.c\u2100.myapp.com"), None
        )

    def test_multiple_hosts_wrong_host(self) -> None:
        self.assertEqual(
            sanitize_redirect(
                ["myapp1.com", "myapp2.com"], "http://notmyapp.com/path/"
            ),
            None,
        )


class UserIsAuthenticatedTest(unittest.TestCase):
    def test_user_is_none(self) -> None:
        self.assertEqual(user_is_authenticated(None), False)

    def test_user_is_not_none(self) -> None:
        self.assertEqual(user_is_authenticated(cast("UserProtocol", object())), True)

    def test_user_has_is_authenticated(self) -> None:
        class User:
            is_authenticated = True

        self.assertEqual(user_is_authenticated(cast("UserProtocol", User())), True)

    def test_user_has_is_authenticated_callable(self) -> None:
        class User:
            def is_authenticated(self) -> bool:
                return True

        self.assertEqual(user_is_authenticated(cast("UserProtocol", User())), True)


class UserIsActiveTest(unittest.TestCase):
    def test_user_is_none(self) -> None:
        self.assertEqual(user_is_active(None), False)

    def test_user_is_not_none(self) -> None:
        self.assertEqual(user_is_active(cast("UserProtocol", object())), True)

    def test_user_has_is_active(self) -> None:
        class User:
            is_active = True

        self.assertEqual(user_is_active(cast("UserProtocol", User())), True)

    def test_user_has_is_active_callable(self) -> None:
        class User:
            def is_active(self) -> bool:
                return True

        self.assertEqual(user_is_active(cast("UserProtocol", User())), True)


class SlugifyTest(unittest.TestCase):
    def test_slugify_formats(self) -> None:
        self.assertEqual(slugify("FooBar"), "foobar")
        self.assertEqual(slugify("Foo Bar"), "foo-bar")
        self.assertEqual(slugify("Foo (Bar)"), "foo-bar")


class BuildAbsoluteURITest(unittest.TestCase):
    host = "http://foobar.com"

    def test_path_none(self) -> None:
        self.assertEqual(build_absolute_uri(self.host), self.host)

    def test_path_empty(self) -> None:
        self.assertEqual(build_absolute_uri(self.host, ""), self.host)

    def test_path_http(self) -> None:
        self.assertEqual(
            build_absolute_uri(self.host, "http://barfoo.com"), "http://barfoo.com"
        )

    def test_path_https(self) -> None:
        self.assertEqual(
            build_absolute_uri(self.host, "https://barfoo.com"), "https://barfoo.com"
        )

    def test_host_ends_with_slash_and_path_starts_with_slash(self) -> None:
        assert self.host, "Subclasses must set the host attribute"
        self.assertEqual(
            build_absolute_uri(f"{self.host}/", "/foo/bar"), "http://foobar.com/foo/bar"
        )

    def test_absolute_uri(self) -> None:
        self.assertEqual(
            build_absolute_uri(self.host, "/foo/bar"), "http://foobar.com/foo/bar"
        )


class PartialPrepareTest(unittest.TestCase):
    def test_django_multivalue_dict_keeps_flat_values(self) -> None:
        class MultiValueDict(dict):
            def dict(self):
                return {key: values[-1] for key, values in self.items()}

        class QueryDict(MultiValueDict):
            pass

        strategy = TestStrategy(TestStorage)
        backend = Mock()
        backend.name = "test-backend"
        response = QueryDict(
            {
                "id": ["123456789"],
                "username": ["demo_user"],
                "first_name": ["Alice"],
            }
        )

        partial = partial_prepare(strategy, backend, 0, response=response)

        self.assertEqual(
            partial.kwargs["response"],
            {
                "id": "123456789",
                "username": "demo_user",
                "first_name": "Alice",
            },
        )


class CleanPartialPipelineTest(unittest.TestCase):
    def test_clean_partial_pipeline_clears_pending_external_resume(self) -> None:
        strategy = TestStrategy(TestStorage)
        partial = TestPartial.prepare("test-backend", 0, {"args": [], "kwargs": {}})
        partial.token = "external-token"
        partial.save()
        strategy.session_set(PARTIAL_TOKEN_PENDING_SESSION_NAME, partial.token)
        strategy.session_set(PARTIAL_TOKEN_PENDING_CONFIRMATION_SESSION_NAME, "nonce")
        strategy.session_set(
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME, {"verification_code": "123456"}
        )

        strategy.clean_partial_pipeline(partial.token)

        self.assertIsNone(TestPartial.load(partial.token))
        self.assertIsNone(strategy.session_get(PARTIAL_TOKEN_PENDING_SESSION_NAME))
        self.assertIsNone(
            strategy.session_get(PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME)
        )
        self.assertIsNone(
            strategy.session_get(PARTIAL_TOKEN_PENDING_CONFIRMATION_SESSION_NAME)
        )


class PartialPipelineData(unittest.TestCase):
    def test_returns_partial_when_uid_and_email_do_match(self) -> None:
        email = "foo@example.com"
        backend = self._backend({"uid": email})
        backend.strategy.request_data.return_value = {backend.ID_KEY: email}
        key, val = ("foo", "bar")
        partial = cast(
            "PartialMixin", partial_pipeline_data(backend, None, *(), **{key: val})
        )
        self.assertIsNotNone(partial)
        self.assertIn(key, partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def test_returns_partial_when_request_token_matches_session_id(self) -> None:
        backend = self._backend(request_data={"partial_token": "session-token"})
        partial = partial_pipeline_data(backend)
        self.assertIsNotNone(partial)
        backend.strategy.partial_load.assert_called_once_with("session-token")

    def test_same_session_external_resume_requires_confirmation(self) -> None:
        response = object()
        backend = self._backend(
            request_data={
                "partial_token": "session-token",
                "verification_code": "123456",
            },
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )
        backend.strategy.partial_pipeline_external_resume_confirmation.return_value = (
            response
        )

        result = partial_pipeline_result(backend)

        self.assertIsNone(result.partial)
        self.assertEqual(result.response, response)
        self.assertFalse(result.halt)
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_SESSION_NAME, "session-token"
        )
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
            {"partial_token": "session-token", "verification_code": "123456"},
        )

    def test_same_session_external_resume_rejects_initial_confirmation(self) -> None:
        response = object()
        backend = self._backend(
            request_data={
                "partial_token": "session-token",
                "partial_pipeline_confirm": "1",
                "verification_code": "123456",
            },
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )
        backend.strategy.partial_pipeline_external_resume_confirmation.return_value = (
            response
        )

        result = partial_pipeline_result(backend)

        self.assertIsNone(result.partial)
        self.assertEqual(result.response, response)
        backend.strategy.partial_pipeline_external_resume_confirmed.assert_not_called()
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_SESSION_NAME, "session-token"
        )
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
            {
                "partial_token": "session-token",
                "partial_pipeline_confirm": "1",
                "verification_code": "123456",
            },
        )

    def test_same_session_external_resume_without_request_data_resumes(self) -> None:
        backend = self._backend(
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )

        result = partial_pipeline_result(backend)

        self.assertIsNotNone(result.partial)
        backend.strategy.partial_pipeline_external_resume_confirmation.assert_not_called()

    def test_same_session_external_resume_without_request_token_requires_confirmation(
        self,
    ) -> None:
        response = object()
        backend = self._backend(
            request_data={"verification_code": "123456"},
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )
        backend.strategy.partial_pipeline_external_resume_confirmation.return_value = (
            response
        )

        result = partial_pipeline_result(backend)

        self.assertIsNone(result.partial)
        self.assertEqual(result.response, response)
        self.assertFalse(result.halt)
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_SESSION_NAME, "session-token"
        )
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
            {"verification_code": "123456"},
        )

    def test_request_token_without_session_match_is_halted(self) -> None:
        backend = self._backend(
            request_data={"partial_token": "attacker-token"},
            session_id="session-token",
            partial_id="attacker-token",
        )
        result = partial_pipeline_result(backend)
        self.assertIsNone(result.partial)
        self.assertIsNone(result.response)
        self.assertTrue(result.halt)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def test_external_resume_stores_pending_token_and_returns_confirmation(
        self,
    ) -> None:
        response = object()
        backend = self._backend(
            request_data={
                "partial_token": "external-token",
                "verification_code": "123456",
            },
            session_id=None,
            partial_id="external-token",
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )
        backend.strategy.partial_pipeline_external_resume_confirmation.return_value = (
            response
        )

        result = partial_pipeline_result(backend)

        self.assertIsNone(result.partial)
        self.assertEqual(result.response, response)
        self.assertFalse(result.halt)
        backend.strategy.partial_pipeline_external_resume_confirmation.assert_called_once()
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_SESSION_NAME, "external-token"
        )
        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
            {"partial_token": "external-token", "verification_code": "123456"},
        )

    def test_external_resume_stores_plain_pending_request_data(self) -> None:
        class MultiValueDict(dict):
            def get(self, key, default=None):
                value = super().get(key, default)
                if isinstance(value, list):
                    return value[-1]
                return value

            def dict(self):
                return {key: values[-1] for key, values in self.items()}

        class QueryDict(MultiValueDict):
            pass

        response = object()
        backend = self._backend(
            request_data=QueryDict(
                {
                    "partial_token": ["external-token"],
                    "verification_code": ["123456"],
                }
            ),
            session_id=None,
            partial_id="external-token",
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )
        backend.strategy.partial_pipeline_external_resume_confirmation.return_value = (
            response
        )

        partial_pipeline_result(backend)

        backend.strategy.session_set.assert_any_call(
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
            {"partial_token": "external-token", "verification_code": "123456"},
        )

    def test_external_resume_without_confirmation_handler_halts(self) -> None:
        backend = self._backend(
            request_data={"partial_token": "external-token"},
            session_id=None,
            partial_id="external-token",
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )

        result = partial_pipeline_result(backend)

        self.assertIsNone(result.partial)
        self.assertIsNone(result.response)
        self.assertTrue(result.halt)
        self.assertEqual(backend.strategy.session_set.call_count, 0)

    def test_unconfirmed_external_resume_halts(self) -> None:
        backend = self._backend(
            request_data={"partial_pipeline_confirm": "1"},
            session_id=None,
            pending_resume={
                "token": "external-token",
                "request": {
                    "partial_token": "external-token",
                    "verification_code": "123456",
                },
            },
            partial_id="external-token",
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )
        backend.strategy.partial_pipeline_external_resume_confirmed.return_value = False

        result = partial_pipeline_result(backend)

        self.assertIsNone(result.partial)
        self.assertIsNone(result.response)
        self.assertTrue(result.halt)

    def test_confirmed_external_resume_uses_pending_request_data(self) -> None:
        backend = self._backend(
            request_data={"partial_pipeline_confirm": "1"},
            session_id=None,
            pending_resume={
                "token": "external-token",
                "request": {
                    "partial_token": "external-token",
                    "verification_code": "123456",
                },
            },
            partial_id="external-token",
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )

        result = partial_pipeline_result(backend, request=object())

        self.assertIsNotNone(result.partial)
        assert result.partial is not None
        self.assertEqual(
            result.partial.kwargs["request"]["partial_token"], "external-token"
        )
        self.assertEqual(
            result.partial.kwargs["request"]["verification_code"], "123456"
        )
        self.assertEqual(
            result.partial.kwargs["request"]["partial_pipeline_confirm"], "1"
        )

    def test_confirmed_same_session_resume_uses_pending_request_data(self) -> None:
        backend = self._backend(
            request_data={
                "partial_token": "session-token",
                "partial_pipeline_confirm": "1",
            },
            pending_resume={
                "token": "session-token",
                "request": {
                    "partial_token": "session-token",
                    "verification_code": "123456",
                },
            },
            partial_data={PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME: True},
        )

        result = partial_pipeline_result(backend, request=object())

        self.assertIsNotNone(result.partial)
        assert result.partial is not None
        self.assertEqual(
            result.partial.kwargs["request"]["partial_token"], "session-token"
        )
        self.assertEqual(
            result.partial.kwargs["request"]["verification_code"], "123456"
        )

    def test_clean_pipeline_when_uid_does_not_match(self) -> None:
        backend = self._backend({"uid": "foo@example.com"})
        backend.strategy.request_data.return_value = {backend.ID_KEY: "bar@example.com"}
        key, val = ("foo", "bar")
        partial = partial_pipeline_data(backend, None, *(), **{key: val})
        self.assertIsNone(partial)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 1)

    def test_kwargs_included_in_result(self) -> None:
        backend = self._backend()
        key, val = ("foo", "bar")
        partial = cast(
            "PartialMixin", partial_pipeline_data(backend, None, *(), **{key: val})
        )
        self.assertIsNotNone(partial)
        self.assertIn(key, partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def test_update_user(self) -> None:
        user = cast("UserProtocol", object())
        backend = self._backend(session_kwargs={"user": None})
        partial = cast("PartialMixin", partial_pipeline_data(backend, user))
        self.assertIsNotNone(partial)
        self.assertIn("user", partial.kwargs)
        self.assertEqual(partial.kwargs["user"], user)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def test_configurable_id_key(self) -> None:
        """Test that ID_KEY can be configured via settings"""
        email = "foo@example.com"
        backend = self._backend({"uid": email})
        # Configure a different ID_KEY via id_key() method
        backend.id_key.return_value = "custom_id"
        backend.strategy.request_data.return_value = {"custom_id": email}
        key, val = ("foo", "bar")
        partial = cast(
            "PartialMixin", partial_pipeline_data(backend, None, *(), **{key: val})
        )
        self.assertIsNotNone(partial)
        self.assertIn(key, partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def _backend(
        self,
        session_kwargs=None,
        request_data=None,
        session_id: str | None = "session-token",
        pending_resume=None,
        partial_id="session-token",
        partial_data=None,
        settings=None,
    ):
        backend = Mock()
        backend.ID_KEY = "email"
        backend.name = "mock-backend"
        backend.id_key.return_value = "email"
        settings = settings or {}

        def setting(name, default=None):
            return settings.get(name, default)

        strategy = Mock()
        strategy.request = None
        strategy.request_data.return_value = request_data or {}
        strategy.to_session_value.side_effect = lambda value: value
        strategy.from_session_value.side_effect = lambda value: value
        session_values = {
            PARTIAL_TOKEN_SESSION_NAME: session_id,
            PARTIAL_TOKEN_PENDING_SESSION_NAME: (pending_resume or {}).get("token"),
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME: (pending_resume or {}).get(
                "request"
            ),
        }
        strategy.session_get.side_effect = lambda name, default=None: (
            session_values.get(name, default)
        )
        partial = TestPartial.prepare(
            backend.name, 0, {"args": [], "kwargs": session_kwargs or {}}
        )
        partial.token = partial_id
        if partial_data:
            partial.data.update(partial_data)
        strategy.partial_load.return_value = partial
        strategy.redirect.return_value = Mock()
        strategy.partial_pipeline_external_resume_confirmation.return_value = None
        strategy.partial_pipeline_external_resume_confirmed.return_value = True

        backend.strategy = strategy
        backend.setting.side_effect = setting
        return backend


class GetKeyAndSecretBasicAuthTest(unittest.TestCase):
    def test_basic_auth_returns_bytes(self) -> None:
        """Test that method returns bytes with base64 encoding"""
        test_setting = {"KEY": "test_key", "SECRET": "test_secret"}
        backend = BaseAuth(strategy=Mock())
        with patch("social_core.backends.base.BaseAuth.setting", new=test_setting.get):
            result = backend.get_key_and_secret_basic_auth()
            expected = b"Basic " + base64.b64encode(b"test_key:test_secret")
            self.assertEqual(result, expected)
            self.assertIsInstance(result, bytes)


class IdKeyConfigurabilityTest(unittest.TestCase):
    """Test that ID_KEY is configurable via settings"""

    def test_id_key_uses_class_attribute_by_default(self) -> None:
        """Test that id_key() returns class attribute when no setting is provided"""
        strategy = Mock()
        strategy.setting = Mock(return_value=None)
        backend = BaseAuth(strategy=strategy)
        backend.ID_KEY = "default_id"

        result = backend.id_key()

        self.assertEqual(result, "default_id")
        strategy.setting.assert_called_once_with(
            "ID_KEY", default=None, backend=backend
        )

    def test_id_key_uses_setting_when_provided(self) -> None:
        """Test that id_key() returns setting value when provided"""
        strategy = Mock()
        strategy.setting = Mock(return_value="custom_id")
        backend = BaseAuth(strategy=strategy)
        backend.ID_KEY = "default_id"

        result = backend.id_key()

        self.assertEqual(result, "custom_id")
        strategy.setting.assert_called_once_with(
            "ID_KEY", default=None, backend=backend
        )

    def test_get_user_id_uses_configurable_id_key(self) -> None:
        """Test that get_user_id() uses the configurable id_key()"""
        strategy = Mock()
        strategy.setting = Mock(return_value="custom_user_id")
        backend = BaseAuth(strategy=strategy)
        backend.ID_KEY = "default_id"

        response = {"custom_user_id": "12345", "default_id": "67890"}
        result = backend.get_user_id({}, response)

        self.assertEqual(result, "12345")
        strategy.setting.assert_called_with("ID_KEY", default=None, backend=backend)
