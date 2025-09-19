"""
Disqus OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/disqus.html
"""

from __future__ import annotations

from typing import Any

from .oauth import BaseOAuth2


class DisqusOAuth2(BaseOAuth2):
    name = "disqus"
    AUTHORIZATION_URL = "https://disqus.com/api/oauth/2.0/authorize/"
    ACCESS_TOKEN_URL = "https://disqus.com/api/oauth/2.0/access_token/"
    REDIRECT_STATE = False
    SCOPE_SEPARATOR = ","
    EXTRA_DATA = [
        ("avatar", "avatar"),
        ("connections", "connections"),
        ("user_id", "user_id"),
        ("email", "email"),
        ("email_hash", "emailHash"),
        ("expires", "expires"),
        ("location", "location"),
        ("meta", "response"),
        ("name", "name"),
        ("username", "username"),
    ]

    def get_user_id(self, details, response):
        return response["response"]["id"]

    def get_user_details(self, response):
        """Return user details from Disqus account"""
        rr = response.get("response", {})
        return {
            "username": rr.get("username", ""),
            "user_id": response.get("user_id", ""),
            "email": rr.get("email", ""),
            "name": rr.get("name", ""),
        }

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        meta_response = dict(response, **response.get("response", {}))
        return super().extra_data(user, uid, meta_response, details, pipeline_kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        _key, secret = self.get_key_and_secret()
        return self.get_json(
            "https://disqus.com/api/3.0/users/details.json",
            params={"access_token": access_token, "api_secret": secret},
        )
