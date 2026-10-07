"""
Tumblr OAuth1 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/tumblr.html
"""

from operator import itemgetter
from typing import Any

from social_core.utils import first

from .oauth import BaseOAuth1


class TumblrOAuth(BaseOAuth1):
    name = "tumblr"
    title = "Tumblr"
    ID_KEY = "uuid"
    LEGACY_ID_KEYS = ("name",)
    MUTABLE_ID_KEYS = ("name",)
    EXTRA_DATA = ["uuid"]
    AUTHORIZATION_URL = "https://www.tumblr.com/oauth/authorize"
    REQUEST_TOKEN_URL = "https://www.tumblr.com/oauth/request_token"
    REQUEST_TOKEN_METHOD = "POST"
    ACCESS_TOKEN_URL = "https://www.tumblr.com/oauth/access_token"

    def get_user_id_for_key(self, details, response, id_key):
        data = response.get("response") or {}
        user = data.get("user") or {}
        blog = first(lambda item: item.get("primary"), user.get("blogs", []))
        return self.get_user_id_from_sources(user, blog, details, id_key=id_key)

    def get_user_id(self, details, response):
        return self.get_user_id_for_key(details, response, self.id_key())

    def get_user_details(self, response):
        # https://www.tumblr.com/docs/en/api/v2#user-methods
        user_info = response["response"]["user"]
        data = {"username": user_info["name"]}
        blog = first(itemgetter("primary"), user_info["blogs"])
        if blog:
            data["fullname"] = blog["title"]
            data["uuid"] = blog.get("uuid")
        return data

    def user_data(self, access_token: dict, *args, **kwargs) -> dict[str, Any] | None:
        return self.get_json(
            "https://api.tumblr.com/v2/user/info",
            auth=self.oauth_auth(access_token, stage="user_info"),
        )
