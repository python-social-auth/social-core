import json
from typing import Any, cast

import responses

from social_core.actions import do_auth
from social_core.exceptions import AuthAssociationError, AuthSessionError
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import get_querystring

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class MixcloudOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.mixcloud.MixcloudOAuth2"
    user_data_url = "https://api.mixcloud.com/me/"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "username": "foobar",
            "cloudcast_count": 0,
            "following_count": 0,
            "url": "http://www.mixcloud.com/foobar/",
            "pictures": {
                "medium": "http://images-mix.netdna-ssl.com/w/100/h/100/q/85/"
                "images/graphics/33_Profile/default_user_600x600-v4.png",
                "320wx320h": "http://images-mix.netdna-ssl.com/w/320/h/320/q/85/"
                "images/graphics/33_Profile/"
                "default_user_600x600-v4.png",
                "extra_large": "http://images-mix.netdna-ssl.com/w/600/h/600/q/85/"
                "images/graphics/33_Profile/"
                "default_user_600x600-v4.png",
                "large": "http://images-mix.netdna-ssl.com/w/300/h/300/q/85/"
                "images/graphics/33_Profile/default_user_600x600-v4.png",
                "640wx640h": "http://images-mix.netdna-ssl.com/w/640/h/640/q/85/"
                "images/graphics/33_Profile/"
                "default_user_600x600-v4.png",
                "medium_mobile": "http://images-mix.netdna-ssl.com/w/80/h/80/q/75/"
                "images/graphics/33_Profile/"
                "default_user_600x600-v4.png",
                "small": "http://images-mix.netdna-ssl.com/w/25/h/25/q/85/images/"
                "graphics/33_Profile/default_user_600x600-v4.png",
                "thumbnail": "http://images-mix.netdna-ssl.com/w/50/h/50/q/85/"
                "images/graphics/33_Profile/"
                "default_user_600x600-v4.png",
            },
            "is_current_user": True,
            "listen_count": 0,
            "updated_time": "2013-03-17T06:26:31Z",
            "following": False,
            "follower": False,
            "key": "/foobar/",
            "created_time": "2013-03-17T06:26:31Z",
            "follower_count": 0,
            "favorite_count": 0,
            "name": "foobar",
        }
    )

    def start_for_user(self, user: User) -> str:
        start_url = do_auth(self.backend, user=user).url
        state = get_querystring(start_url)["state"]
        context = self.strategy.session_get("mixcloud_state")
        assert context is not None
        self.assertEqual(context["state"], state)
        self.assertEqual(context["user_id"], str(user.id))
        return start_url

    def prepare_callback(self, user: User) -> None:
        start_url = self.start_for_user(user)
        target_url = self.auth_handlers(start_url)
        self.strategy.set_request_data(get_querystring(target_url), self.backend)
        self.pre_complete_callback(start_url)

    def complete_for_user(self, user: User) -> User:
        self.prepare_callback(user)
        result = self.backend.complete(user=user)
        self.assertIs(result, user)
        return cast("User", result)

    def test_login(self) -> None:
        user = self.complete_for_user(User("existing"))
        social = TestUserSocialAuth.get_social_auth("mixcloud", "foobar")
        self.assertIs(social.user, user)
        self.assertEqual(len(User.cache), 1)

    def test_partial_pipeline(self) -> None:
        victim = User("victim")
        attacker = User("attacker")
        social = TestUserSocialAuth.create_social_auth(victim, "foobar", "mixcloud")
        self.prepare_callback(attacker)
        with self.assertRaises(AuthAssociationError):
            self.backend.complete(user=attacker)
        self.assertIs(social.user, victim)
        self.assertEqual(attacker.social, [])

    def test_start_requires_authenticated_user(self) -> None:
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend)
        anonymous = User("anonymous")
        cast(Any, anonymous).is_authenticated = False  # noqa: TC006
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend, user=anonymous)

    def test_direct_start_requires_prepared_context(self) -> None:
        with self.assertRaises(AuthSessionError):
            self.backend.start()

    def test_auth_url_parameters(self) -> None:
        self.start_for_user(User("existing"))
        self.check_parameters_in_authorization_url()

    def test_state_cannot_be_replayed(self) -> None:
        user = User("existing")
        self.complete_for_user(user)
        calls = len(responses.calls)
        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)
        self.assertEqual(len(responses.calls), calls)
