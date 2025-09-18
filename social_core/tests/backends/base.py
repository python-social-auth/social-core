from __future__ import annotations

import unittest
from typing import Generic, TypeVar

import requests
import responses

from social_core.backends.base import BaseAuth
from social_core.backends.utils import load_backends, user_backends_data
from social_core.tests.models import (
    TestAssociation,
    TestCode,
    TestNonce,
    TestStorage,
    TestUserSocialAuth,
    User,
)
from social_core.tests.strategy import TestStrategy
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME, module_member, parse_qs

BackendT = TypeVar("BackendT", bound=BaseAuth)


class BaseBackendTest(unittest.TestCase, Generic[BackendT]):
    backend: BackendT
    backend_path: str = ""
    name: str = ""
    complete_url = ""
    raw_complete_url = "/complete/{0}"
    expected_username: str = ""

    def setUp(self) -> None:
        responses.start()
        Backend = module_member(self.backend_path)
        self.strategy = TestStrategy(TestStorage)
        self.backend = Backend(self.strategy, redirect_uri=self.complete_url)
        self.name = self.backend.name.upper().replace("-", "_")
        self.complete_url = self.strategy.build_absolute_uri(
            self.raw_complete_url.format(self.backend.name)
        )
        backends = (
            self.backend_path,
            "social_core.tests.backends.test_broken.BrokenBackendAuth",
        )
        self.strategy.set_settings({"SOCIAL_AUTH_AUTHENTICATION_BACKENDS": backends})
        self.strategy.set_settings(self.extra_settings())
        # Force backends loading to trash PSA cache
        load_backends(backends, force_load=True)
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        TestNonce.reset_cache()
        TestAssociation.reset_cache()
        TestCode.reset_cache()

    def tearDown(self) -> None:
        del self.backend
        self.strategy = None
        self.name = ""
        self.complete_url = None
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        TestNonce.reset_cache()
        TestAssociation.reset_cache()
        TestCode.reset_cache()
        responses.stop()
        responses.reset()

    def extra_settings(self) -> dict[str, str]:
        return {}

    def do_start(self):
        raise NotImplementedError("Implement in subclass")

    def do_login(self):
        user = self.do_start()
        username = self.expected_username
        self.assertEqual(user.username, username)
        self.assertEqual(self.strategy.session_get("username"), username)
        self.assertEqual(self.strategy.get_user(user.id), user)
        self.assertEqual(self.backend.get_user(user.id), user)
        user_backends = user_backends_data(
            user,
            self.strategy.get_setting("SOCIAL_AUTH_AUTHENTICATION_BACKENDS"),
            self.strategy.storage,
        )
        self.assertEqual(len(list(user_backends.keys())), 3)
        self.assertEqual("associated" in user_backends, True)
        self.assertEqual("not_associated" in user_backends, True)
        self.assertEqual("backends" in user_backends, True)
        self.assertEqual(len(user_backends["associated"]), 1)
        self.assertEqual(len(user_backends["not_associated"]), 1)
        self.assertEqual(len(user_backends["backends"]), 2)
        return user

    def pipeline_settings(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.pipeline.social_auth.auth_allowed",
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.tests.pipeline.ask_for_slug",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.user.get_username",
                    "social_core.pipeline.social_auth.associate_by_email",
                    "social_core.pipeline.user.create_user",
                    "social_core.pipeline.social_auth.associate_user",
                    "social_core.pipeline.social_auth.load_extra_data",
                    "social_core.tests.pipeline.set_password",
                    "social_core.tests.pipeline.set_slug",
                    "social_core.pipeline.user.user_details",
                )
            }
        )

    def pipeline_handlers(self, url) -> None:
        responses.add(responses.GET, url, status=200, body="foobar")
        responses.add(responses.POST, url, status=200)

    def pipeline_password_handling(self, url):
        password = "foobar"
        requests.get(url, timeout=1)
        requests.post(url, data={"password": password}, timeout=1)

        data = parse_qs(responses.calls[-1].request.body)
        self.assertEqual(data["password"], password)
        self.strategy.session_set("password", data["password"])
        return password

    def pipeline_slug_handling(self, url):
        slug = "foo-bar"
        requests.get(url, timeout=1)
        requests.post(url, data={"slug": slug}, timeout=1)

        data = parse_qs(responses.calls[-1].request.body)
        self.assertEqual(data["slug"], slug)
        self.strategy.session_set("slug", data["slug"])
        return slug

    def do_partial_pipeline(self):
        url = self.strategy.build_absolute_uri("/password")
        self.pipeline_settings()
        redirect = self.do_start()
        self.assertEqual(redirect.url, url)
        self.pipeline_handlers(url)

        password = self.pipeline_password_handling(url)
        token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
        partial = self.strategy.partial_load(token)
        self.assertEqual(partial.backend, self.backend.name)
        redirect = self.backend.continue_pipeline(partial)

        url = self.strategy.build_absolute_uri("/slug")
        self.assertEqual(redirect.url, url)
        self.pipeline_handlers(url)
        slug = self.pipeline_slug_handling(url)

        token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
        partial = self.strategy.partial_load(token)
        self.assertEqual(partial.backend, self.backend.name)
        user = self.backend.continue_pipeline(partial)

        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(user.slug, slug)
        self.assertEqual(user.password, password)
        return user
