import unittest
from unittest.mock import Mock

from social_core.utils import (
    build_absolute_uri,
    partial_pipeline_data,
    sanitize_redirect,
    slugify,
    user_is_active,
    user_is_authenticated,
)

from .models import TestPartial


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
        self.assertEqual(user_is_authenticated(object()), True)

    def test_user_has_is_authenticated(self) -> None:
        class User:
            is_authenticated = True

        self.assertEqual(user_is_authenticated(User()), True)

    def test_user_has_is_authenticated_callable(self) -> None:
        class User:
            def is_authenticated(self) -> bool:
                return True

        self.assertEqual(user_is_authenticated(User()), True)


class UserIsActiveTest(unittest.TestCase):
    def test_user_is_none(self) -> None:
        self.assertEqual(user_is_active(None), False)

    def test_user_is_not_none(self) -> None:
        self.assertEqual(user_is_active(object()), True)

    def test_user_has_is_active(self) -> None:
        class User:
            is_active = True

        self.assertEqual(user_is_active(User()), True)

    def test_user_has_is_active_callable(self) -> None:
        class User:
            def is_active(self) -> bool:
                return True

        self.assertEqual(user_is_active(User()), True)


class SlugifyTest(unittest.TestCase):
    def test_slugify_formats(self) -> None:
        self.assertEqual(slugify("FooBar"), "foobar")
        self.assertEqual(slugify("Foo Bar"), "foo-bar")
        self.assertEqual(slugify("Foo (Bar)"), "foo-bar")


class BuildAbsoluteURITest(unittest.TestCase):
    def setUp(self) -> None:
        self.host = "http://foobar.com"

    def tearDown(self) -> None:
        self.host = None

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
        self.assertTrue(key in partial.kwargs)
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
        self.assertTrue(key in partial.kwargs)
        self.assertEqual(partial.kwargs[key], val)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def test_update_user(self) -> None:
        user = object()
        backend = self._backend(session_kwargs={"user": None})
        partial = partial_pipeline_data(backend, user)
        self.assertTrue("user" in partial.kwargs)
        self.assertEqual(partial.kwargs["user"], user)
        self.assertEqual(backend.strategy.clean_partial_pipeline.call_count, 0)

    def _backend(self, session_kwargs=None):
        backend = Mock()
        backend.ID_KEY = "email"
        backend.name = "mock-backend"

        strategy = Mock()
        strategy.request = None
        strategy.request_data.return_value = {}
        strategy.session_get.return_value = object()
        strategy.partial_load.return_value = TestPartial.prepare(
            backend.name, 0, {"args": [], "kwargs": session_kwargs or {}}
        )

        backend.strategy = strategy
        return backend
