from __future__ import annotations

import datetime as dt
from typing import Any

from .oauth import BaseOAuth2


class AsanaOAuth2(BaseOAuth2):
    name = "asana"
    title = "Asana"
    ID_KEY = "gid"
    REQUIRES_USER_ID = True
    AUTHORIZATION_URL = "https://app.asana.com/-/oauth_authorize"
    ACCESS_TOKEN_URL = "https://app.asana.com/-/oauth_token"
    REFRESH_TOKEN_URL = "https://app.asana.com/-/oauth_token"
    REDIRECT_STATE = False
    USER_DATA_URL = "https://app.asana.com/api/1.0/users/me"
    EXTRA_DATA = [
        ("expires_in", "expires_in"),
        ("refresh_token", "refresh_token"),
        ("name", "name"),
        ("gid", "gid"),
    ]

    def get_user_details(self, response):
        data = response["data"]
        fullname = data["name"]
        first_name = None
        last_name = None
        return {
            "email": data["email"],
            "username": data["email"],
            "fullname": fullname,
            "last_name": last_name,
            "first_name": first_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        response = self.get_json(
            self.USER_DATA_URL, headers={"Authorization": f"Bearer {access_token}"}
        )
        if response is not None and isinstance(response.get("data"), dict):
            response["gid"] = response["data"].get("gid")
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
        if self.setting("ESTIMATE_EXPIRES_ON"):
            expires_on = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                seconds=data["expires"]
            )
            data["expires_on"] = expires_on.isoformat()
        return data
