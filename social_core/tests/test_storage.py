import unittest
from typing import cast
from unittest.mock import Mock, patch

from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.storage import (
    AssociationMixin,
    BaseStorage,
    CodeMixin,
    NonceMixin,
    UserMixin,
)
from social_core.strategy import BaseStrategy

from .models import TestStorage, User
from .strategy import TestStrategy

NOT_IMPLEMENTED_MSG = "Implement in subclass"


class BrokenUser(UserMixin):
    def save(self) -> None:
        pass


class BrokenAssociation(AssociationMixin):
    pass


class BrokenNonce(NonceMixin):
    pass


class BrokenCode(CodeMixin):
    pass


class BrokenStrategy(BaseStrategy):
    pass


class BrokenStrategyWithSettings(BrokenStrategy):
    def get_setting(self, name):
        raise AttributeError


class BrokenStorage(BaseStorage):
    pass


class BrokenUserTests(unittest.TestCase):
    user = BrokenUser

    def test_unusable_refresh_tokens_preserve_stored_credentials(self):
        strategy = TestStrategy(TestStorage)
        strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        backend = BaseOAuth2(strategy)
        social = BrokenUser()
        social.extra_data = {
            "refresh_token": "refresh",
            "access_token": "previous-token",
        }
        original_data = social.extra_data.copy()
        tokens: tuple[object, ...] = (None, "", False, 0, [], {})
        for payload in ({}, *({"access_token": token} for token in tokens)):
            response = Mock()
            response.json.return_value = payload
            with (
                self.subTest(payload=payload),
                patch.object(social, "get_backend_instance", return_value=backend),
                patch("requests.request", return_value=response),
                patch.object(
                    social, "set_extra_data", wraps=social.set_extra_data
                ) as set_extra_data,
                patch.object(social, "save") as save,
                self.assertRaises(AuthResponseError) as caught,
            ):
                social.refresh_token(strategy)
            self.assertEqual(caught.exception.code, "missing_claim")
            self.assertEqual(caught.exception.claim, "access_token")
            self.assertEqual(caught.exception.stage, "refresh")
            self.assertEqual(social.extra_data, original_data)
            set_extra_data.assert_not_called()
            save.assert_not_called()

    def test_missing_backend_is_the_only_ignored_configuration_failure(self):
        user = BrokenUser()
        user.extra_data = {"refresh_token": "token", "access_token": "expired"}
        for code in ("backend_missing", "invalid_setting", "missing_setting"):
            error = AuthConfigurationError(code=code)
            strategy = Mock(spec=BaseStrategy)
            strategy.get_backend.side_effect = error
            with self.subTest(code=code):
                if code == "backend_missing":
                    self.assertIsNone(user.get_backend_instance(strategy))
                    user.refresh_token(strategy)
                else:
                    with self.assertRaises(AuthConfigurationError) as caught:
                        user.refresh_token(strategy)
                    self.assertIs(caught.exception, error)

    def test_get_username(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.get_username(User("foobar"))

    def test_user_model(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.user_model()

    def test_username_max_length(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.username_max_length()

    def test_get_user(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.get_user(1)

    def test_get_social_auth(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.get_social_auth("foo", "1")

    def test_get_social_auth_for_user(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.get_social_auth_for_user(User("foobar"))

    def test_get_social_auth_by_extra_data(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.get_social_auth_by_extra_data("foo", "id", "1")

    def test_create_social_auth(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.create_social_auth(User("foobar"), "1", "foo")

    def test_migrate_social_auth(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.migrate_social_auth(BrokenUser(), "1", "id")

    def test_disconnect(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.user.disconnect(BrokenUser())


class BrokenAssociationTests(unittest.TestCase):
    association = BrokenAssociation

    def test_store(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.association.store("http://foobar.com", BrokenAssociation())

    def test_get(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.association.get()

    def test_remove(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.association.remove([1, 2, 3])


class BrokenNonceTests(unittest.TestCase):
    nonce = BrokenNonce

    def test_use(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.nonce.use("http://foobar.com", 1364951922, "foobar123")


class BrokenCodeTest(unittest.TestCase):
    code = BrokenCode

    def test_get_code(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.code.get_code("foobar")


class BrokenStrategyTests(unittest.TestCase):
    strategy: BrokenStrategy

    def setUp(self) -> None:
        self.strategy = BrokenStrategy(storage=BrokenStorage)

    def test_redirect(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.redirect("http://foobar.com")

    def test_get_setting(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.get_setting("foobar")

    def test_html(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.html("<p>foobar</p>")

    def test_request_data(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.request_data()

    def test_request_host(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.request_host()

    def test_session_get(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.session_get("foobar")

    def test_session_set(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.session_set("foobar", 123)

    def test_session_pop(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.session_pop("foobar")

    def test_build_absolute_uri(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.build_absolute_uri("/foobar")

    def test_render_html_with_tpl(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.render_html("foobar.html", context={})

    def test_render_html_with_html(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            self.strategy.render_html(html="<p>foobar</p>", context={})

    def test_render_html_with_none(self) -> None:
        with self.assertRaisesRegex(ValueError, "Missing template or html parameters"):
            self.strategy.render_html()

    def test_is_integrity_error(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, NOT_IMPLEMENTED_MSG):
            cast("BrokenStorage", self.strategy.storage).is_integrity_error(None)

    def test_random_string(self) -> None:
        self.assertIsInstance(self.strategy.random_string(), str)
