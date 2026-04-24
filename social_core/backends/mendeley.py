"""Mendeley OAuth2 backend."""

from typing import Any

from .oauth import BaseOAuth2

BASE_EXTRA_DATA = [("profile_id", "profile_id"), ("name", "name"), ("bio", "bio")]


class MendeleyMixin:
    SCOPE_SEPARATOR = "+"

    def get_user_id(self, details, response):
        return response["id"]

    def get_user_details(self, response):
        """Return user details from Mendeley account"""
        profile_id = response["id"]
        name = response["display_name"]
        bio = response["link"]
        return {"profile_id": profile_id, "name": name, "bio": bio}

    def user_data(self, access_token, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        values = self.get_user_data(access_token)
        values.update(values)
        return values

    def get_user_data(self, access_token):
        raise NotImplementedError("Implement in subclass")


class MendeleyOAuth2(MendeleyMixin, BaseOAuth2):
    name = "mendeley-oauth2"
    AUTHORIZATION_URL = "https://api-oauth2.mendeley.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://api-oauth2.mendeley.com/oauth/token"
    DEFAULT_SCOPE = ["all"]
    REDIRECT_STATE = False
    EXTRA_DATA = [
        *BASE_EXTRA_DATA,
        ("refresh_token", "refresh_token"),
        ("expires_in", "expires_in"),
        ("token_type", "token_type"),
    ]

    def get_user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
            "https://api.mendeley.com/profiles/me/",
            headers={"Authorization": f"Bearer {access_token}"},
        )
