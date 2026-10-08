"""
Evernote OAuth1 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/evernote.html
"""

from __future__ import annotations

from typing import Any

from .oauth import BaseOAuth1


class EvernoteOAuth(BaseOAuth1):
    """
    Evernote OAuth authentication backend.

    Possible Values:
       {'edam_expires': ['1367525289541'],
        'edam_noteStoreUrl': [
            'https://www.evernote.com/shard/s1/notestore'
        ],
        'edam_shard': ['s1'],
        'edam_userId': ['123841'],
        'edam_webApiUrlPrefix': ['https://www.evernote.com/shard/s1/'],
        'oauth_token': [
            'S=s1:U=1e3c1:E=13e66dbee45:C=1370f2ac245:P=185:A=my_user:' \
            'H=411443c5e8b20f8718ed382a19d4ae38'
        ]}
    """

    name = "evernote"
    title = "Evernote"
    ID_KEY = "edam_userId"
    AUTHORIZATION_URL = "https://www.evernote.com/OAuth.action"
    REQUEST_TOKEN_URL = "https://www.evernote.com/oauth"
    ACCESS_TOKEN_URL = "https://www.evernote.com/oauth"
    ACCESS_TOKEN_METHOD = "GET"
    EXTRA_DATA = [
        ("access_token", "access_token"),
        ("oauth_token", "oauth_token"),
        ("edam_noteStoreUrl", "store_url"),
        ("edam_expires", "expires"),
    ]

    def get_user_details(self, response):
        """Return user details from Evernote account"""
        return {"username": response["edam_userId"], "email": ""}

    def access_token(self, token):
        """Return request for access token value"""
        response = self.get_querystring(
            self.ACCESS_TOKEN_URL,
            auth=self.oauth_auth(token, stage="token_exchange"),
            stage="token_exchange",
        )
        self._process_error(response, stage="token_exchange")
        return response

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        data = super().extra_data(user, uid, response, details, pipeline_kwargs)
        # Evernote returns expiration timestamp in milliseconds, so it needs to
        # be normalized.
        if "expires" in data:
            data["expires"] = int(data["expires"]) / 1000
        return data

    def user_data(self, access_token: dict, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        return access_token.copy()
