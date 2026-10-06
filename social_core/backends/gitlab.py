"""
GitLab OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/gitlab.html

Thanks to [@saily](https://github.com/saily) who published an
implementation for GitLab support on his blog post [Weblate with
GitLab as OAuth provider](http://widerin.net/blog/weblate-gitlab-oauth-login/).
His code was a great reference when working on this implementation.
"""

from typing import Any

from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.groups import read_groups

from .oauth import BaseOAuth2


class GitLabOAuth2(BaseOAuth2):
    """GitLab OAuth authentication backend"""

    name = "gitlab"
    title = "GitLab"
    icon = "gitlab.svg"
    API_URL = "https://gitlab.com"
    AUTHORIZATION_URL = "https://gitlab.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://gitlab.com/oauth/token"
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ["read_user"]
    EXTRA_DATA = [
        ("id", "id"),
        ("expires_in", "expires_in"),
        ("refresh_token", "refresh_token"),
    ]

    def get_scope(self) -> list[str]:
        scope = super().get_scope()
        if self.setting("GROUPS_ENABLED", False) and not {
            "read_api",
            "api",
        }.intersection(scope):
            return [*scope, "read_api"]
        return scope

    def api_url(self, path) -> str:
        api_url = self.setting("API_URL") or self.API_URL
        return f"{api_url.rstrip('/')}{path}"

    def authorization_url(self):
        return self.api_url("/oauth/authorize")

    def access_token_url(self):
        return self.api_url("/oauth/token")

    def get_user_details(self, response):
        """Return user details from GitLab account"""
        fullname = response.get("name")
        first_name = ""
        last_name = ""
        return {
            "username": response.get("username"),
            "email": response.get("email") or "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        data = self.get_json(
            self.api_url("/api/v4/user"), params={"access_token": access_token}
        )
        if self.setting("GROUPS_ENABLED", False):
            data["groups"] = self.fetch_groups(access_token)
        return data

    def fetch_groups(self, access_token: str) -> list[str]:
        """Fetch a complete membership snapshot before entering the pipeline."""
        identifier = self.setting("GROUPS_IDENTIFIER", "full_path")
        if identifier not in {"id", "full_path"}:
            raise AuthConfigurationError(
                self,
                code="invalid_setting",
                parameter="GROUPS_IDENTIFIER",
                stage="user_info",
            )
        groups = []
        page = 1
        while True:
            result = self.request(
                self.api_url("/api/v4/groups"),
                headers={"Authorization": f"Bearer {access_token}"},
                params={
                    "all_available": "false",
                    "min_access_level": 5,
                    "per_page": 100,
                    "page": page,
                    "order_by": "id",
                    "sort": "asc",
                },
                stage="user_info",
            )
            try:
                entries = result.json()
            except ValueError as error:
                raise AuthResponseError(
                    self, code="malformed_response", stage="user_info"
                ) from error
            if not isinstance(entries, list):
                raise AuthResponseError(
                    self, code="malformed_response", stage="user_info"
                )
            for entry in entries:
                value = entry.get(identifier) if isinstance(entry, dict) else None
                valid = (
                    isinstance(value, int) and not isinstance(value, bool) and value > 0
                    if identifier == "id"
                    else isinstance(value, str) and bool(value)
                )
                if not valid:
                    raise AuthResponseError(
                        self, code="invalid_claim", claim=identifier, stage="user_info"
                    )
                groups.append(str(value))
            next_page = result.headers.get("X-Next-Page")
            if next_page is not None:
                if not next_page:
                    break
                if not next_page.isdecimal() or int(next_page) != page + 1:
                    raise AuthResponseError(
                        self, code="malformed_response", stage="user_info"
                    )
            elif len(entries) < 100:
                break
            page += 1
        return groups

    def get_user_groups(self, response) -> list[str] | None:
        if not self.setting("GROUPS_ENABLED", False):
            return None
        return read_groups(self, response, "groups")
