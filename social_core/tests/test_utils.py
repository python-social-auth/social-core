import base64
import unittest
from typing import TYPE_CHECKING, cast
from unittest.mock import Mock, patch

from social_core.backends.base import BaseAuth
from social_core.utils import (
    build_absolute_uri,
    partial_pipeline_data,
    sanitize_redirect,
    slugify,
    user_is_active,
    user_is_authenticated,
)

from .models import TestPartial

if TYPE_CHECKING:
    from social_core.storage import UserProtocol


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
            build_absolute_uri(self.host + "/", "/foo/bar"), "http://foobar.com/foo/bar"
        )

    def test_absolute_uri(self) -> None:
        self.assertEqual(
            build_absolute_uri(self.host, "/foo/bar"), "http://foobar.com/foo/bar"
        )


class PartialPipelineData(unittest.TestCase):
    def test_returns_partial_when_uid_and_email_do_match(self) -> None:
        email = "foo@example.com"
        backend = self._backend({"uid": email})
        backend.strategy.request_data.return_value = {backend.ID_KEY: email}
        key, val = ("foo", "bar")
        partial = partial_pipeline_data(backend, None, *(), **{key: val})
        self.assertIn(key, partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

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
        partial = partial_pipeline_data(backend, None, *(), **{key: val})
        self.assertIn(key, partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def test_update_user(self) -> None:
        user = object()
        backend = self._backend(session_kwargs={"user": None})
        partial = partial_pipeline_data(backend, user)
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
        partial = partial_pipeline_data(backend, None, *(), **{key: val})
        self.assertIn(key, partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def _backend(self, session_kwargs=None):
        backend = Mock()
        backend.ID_KEY = "email"
        backend.name = "mock-backend"
        backend.id_key.return_value = "email"

        strategy = Mock()
        strategy.request = None
        strategy.request_data.return_value = {}
        strategy.session_get.return_value = object()
        strategy.partial_load.return_value = TestPartial.prepare(
            backend.name, 0, {"args": [], "kwargs": session_kwargs or {}}
        )

        backend.strategy = strategy
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
