import unittest
from unittest.mock import patch

from social_core.backends.email import EmailAuth
from social_core.backends.github import GithubOAuth2
from social_core.backends.twitch import TwitchOAuth2, TwitchOpenIdConnect
from social_core.backends.utils import (
    BACKENDSCACHE,
    get_backend,
    load_backends,
    user_backends_data,
)
from social_core.exceptions import AuthConfigurationError
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy


class BaseBackendUtilsTest(unittest.TestCase):
    strategy: TestStrategy

    def setUp(self) -> None:
        self.strategy = TestStrategy(storage=TestStorage)

    def tearDown(self) -> None:
        del self.strategy


class LoadBackendsTest(BaseBackendUtilsTest):
    def test_load_backends(self) -> None:
        loaded_backends = load_backends(
            (
                "social_core.backends.github.GithubOAuth2",
                "social_core.backends.facebook.FacebookOAuth2",
                "social_core.backends.flickr.FlickrOAuth",
            ),
            force_load=True,
        )
        keys = list(loaded_backends.keys())
        self.assertEqual(keys, ["github", "facebook", "flickr"])

        backends = ()
        loaded_backends = load_backends(backends, force_load=True)
        self.assertEqual(len(list(loaded_backends.keys())), 0)

    def test_load_backends_per_setting(self) -> None:
        load_backends(("social_core.backends.email.EmailAuth",), force_load=True)
        loaded_backends = load_backends(("social_core.backends.github.GithubOAuth2",))
        self.assertEqual(list(loaded_backends.keys()), ["github"])


class GetBackendTest(BaseBackendUtilsTest):
    def test_get_backend(self) -> None:
        backend = get_backend(
            (
                "social_core.backends.github.GithubOAuth2",
                "social_core.backends.facebook.FacebookOAuth2",
                "social_core.backends.flickr.FlickrOAuth",
            ),
            "github",
        )
        self.assertEqual(backend, GithubOAuth2)

    def test_get_missing_backend(self) -> None:
        with assert_auth_error(self, AuthConfigurationError, "backend_missing"):
            get_backend(
                (
                    "social_core.backends.github.GithubOAuth2",
                    "social_core.backends.facebook.FacebookOAuth2",
                    "social_core.backends.flickr.FlickrOAuth",
                ),
                "foobar",
            )

    def test_get_backend_enabled_elsewhere(self) -> None:
        # A backend loaded for another AUTHENTICATION_BACKENDS value in the
        # same process must not become available here.
        email_backends = ("social_core.backends.email.EmailAuth",)
        github_backends = ("social_core.backends.github.GithubOAuth2",)
        self.assertEqual(get_backend(email_backends, "email"), EmailAuth)
        with assert_auth_error(self, AuthConfigurationError, "backend_missing"):
            get_backend(github_backends, "email")
        self.assertEqual(get_backend(github_backends, "github"), GithubOAuth2)
        self.assertEqual(get_backend(email_backends, "email"), EmailAuth)

    def test_get_backend_accepts_one_shot_iterable(self) -> None:
        configured = ("social_core.backends.github.GithubOAuth2",)
        with patch.dict(BACKENDSCACHE, {configured: {}}):
            self.assertEqual(get_backend(iter(configured), "github"), GithubOAuth2)

    def test_get_backend_same_name(self) -> None:
        oauth2_backends = ("social_core.backends.twitch.TwitchOAuth2",)
        oidc_backends = ("social_core.backends.twitch.TwitchOpenIdConnect",)
        self.assertEqual(get_backend(oauth2_backends, "twitch"), TwitchOAuth2)
        self.assertEqual(get_backend(oidc_backends, "twitch"), TwitchOpenIdConnect)
        self.assertEqual(get_backend(oauth2_backends, "twitch"), TwitchOAuth2)

    def test_strategy_get_backend_enabled_elsewhere(self) -> None:
        email_backends = ("social_core.backends.email.EmailAuth",)
        github_backends = ("social_core.backends.github.GithubOAuth2",)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_AUTHENTICATION_BACKENDS": email_backends}
        )
        other_strategy = TestStrategy(storage=TestStorage)
        other_strategy.set_settings(
            {"SOCIAL_AUTH_AUTHENTICATION_BACKENDS": github_backends}
        )
        self.assertIsInstance(self.strategy.get_backend("email"), EmailAuth)
        with assert_auth_error(self, AuthConfigurationError, "backend_missing"):
            other_strategy.get_backend("email")


class UserBackendsDataTest(BaseBackendUtilsTest):
    def test_user_backends_data_per_setting(self) -> None:
        load_backends(("social_core.backends.email.EmailAuth",), force_load=True)
        data = user_backends_data(
            None, ("social_core.backends.github.GithubOAuth2",), TestStorage
        )
        self.assertEqual(data["backends"], ["github"])
        self.assertEqual(data["not_associated"], ["github"])
        self.assertEqual(data["associated"], [])
