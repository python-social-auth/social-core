"""
Qiita OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/qiita.html
    http://qiita.com/api/v2/docs#get-apiv2oauthauthorize
    https://qiita.com/api/v2/docs#get-apiv2authenticated_user
"""

import json

from social_core.exceptions import AuthException

from .oauth import BaseOAuth2


class QiitaOAuth2(BaseOAuth2):
    """Qiita OAuth authentication backend"""

    name = "qiita"

    AUTHORIZATION_URL = "https://qiita.com/api/v2/oauth/authorize"
    ACCESS_TOKEN_URL = "https://qiita.com/api/v2/access_tokens"
    ACCESS_TOKEN_METHOD = "POST"
    SCOPE_SEPARATOR = " "
    REDIRECT_STATE = True
    EXTRA_DATA = [
        ("description", "description"),
        ("facebook_id", "facebook_id"),
        ("followees_count", "followees_count"),
        ("followers_count", "followers_count"),
        ("github_login_name", "github_login_name"),
        ("id", "id"),
        ("items_count", "items_count"),
        ("linkedin_id", "linkedin_id"),
        ("location", "location"),
        ("name", "name"),
        ("organization", "organization"),
        ("permanent_id", "permanent_id"),
        ("profile_image_url", "profile_image_url"),
        ("team_only", "team_only"),
        ("twitter_screen_name", "twitter_screen_name"),
        ("website_url", "website_url"),
        ("image_monthly_upload_limit", "image_monthly_upload_limit"),
        ("image_monthly_upload_remaining", "image_monthly_upload_remaining"),
    ]

    # TODO: I am pretty sure this method returns the wrong type; it should
    # return a dict
    def auth_complete_params(self, state=None):  # type: ignore[reportIncompatibleMethodOverride]
        data = super().auth_complete_params(state)
        if "grant_type" in data:
            del data["grant_type"]
        if "redirect_uri" in data:
            del data["redirect_uri"]
        return json.dumps(data)

    def auth_headers(self):
        return {"Content-Type": "application/json"}

    def request_access_token(self, *args, **kwargs):
        data = super().request_access_token(*args, **kwargs)
        data.update({"access_token": data["token"]})
        return data

    def get_user_details(self, response):
        """Return user details from Qiita account"""
        return {
            "username": response["id"],
            "fullname": response["name"],
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
            "https://qiita.com/api/v2/authenticated_user",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    def get_user_id(self, details, response):
        """Return user id"""
        user_id = None
        if self.setting("IDENTIFIED_BY_PERMANENT_ID"):
            user_id = response.get("permanent_id")
        else:
            user_id = response.get("id")

        if user_id is not None:
            return str(user_id)
        raise AuthException("failed to get user id")
