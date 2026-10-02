"""
Github OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/github.html
"""

from typing import Any
from urllib.parse import urljoin

from social_core.exceptions import (
    AuthPolicyError,
    AuthProviderError,
    AuthResponseError,
    SocialAuthBaseException,
)

from .oauth import BaseOAuth2


class GithubOAuth2(BaseOAuth2):
    """Github OAuth authentication backend"""

    name = "github"
    title = "GitHub"
    icon = "github.svg"
    API_URL = "https://api.github.com/"
    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
    SCOPE_SEPARATOR = ","
    REDIRECT_STATE = False
    STATE_PARAMETER = True
    EXTRA_DATA = [
        ("id", "id"),
        ("expires_in", "expires_in"),
        ("login", "login"),
        ("refresh_token", "refresh_token"),
    ]

    def api_url(self) -> str:
        return self.API_URL

    def get_user_details(self, response):
        """Return user details from Github account"""
        fullname = response.get("name")
        first_name = ""
        last_name = ""
        return {
            "username": response.get("login"),
            "email": response.get("email") or "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        data = self._user_data(access_token)
        if not data.get("email") or "user:email" in self.get_scope():
            try:
                emails = self._user_data(access_token, "/emails")
            except (AuthProviderError, AuthResponseError):
                emails = []
            except SocialAuthBaseException:
                raise
            except (ValueError, TypeError):
                emails = []
            else:
                data["emails"] = emails

            if emails:
                email = emails[0]
                primary_emails = [
                    e for e in emails if not isinstance(e, dict) or e.get("primary")
                ]
                if primary_emails:
                    email = primary_emails[0]
                data["email"] = email["email"]
        return data

    def _user_data(self, access_token, path=None):
        url = urljoin(self.api_url(), f"user{path or ''}")
        return self.get_json(url, headers={"Authorization": f"token {access_token}"})


class GithubMemberOAuth2(GithubOAuth2):
    no_member_string = ""

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        user_data = super().user_data(access_token, *args, **kwargs)
        headers = {"Authorization": f"token {access_token}"}
        try:
            self.request(self.member_url(user_data), headers=headers)
        except AuthProviderError as err:
            # if the user is a member of the organization, response code
            # will be 204, see http://bit.ly/ZS6vFl
            if err.status_code == 404:
                raise AuthPolicyError(
                    self,
                    "User doesn't belong to the organization",
                    code="membership_required",
                    stage="user_info",
                ) from err
            raise
        return user_data

    def member_url(self, user_data):
        raise NotImplementedError("Implement in subclass")


class GithubOrganizationOAuth2(GithubMemberOAuth2):
    """Github OAuth2 authentication backend for organizations"""

    name = "github-org"
    title = "GitHub Organization"
    icon = "github.svg"
    no_member_string = "User doesn't belong to the organization"

    def member_url(self, user_data):
        return urljoin(
            self.api_url(),
            f"orgs/{self.setting('NAME')}/members/{user_data.get('login')}",
        )


class GithubTeamOAuth2(GithubMemberOAuth2):
    """Github OAuth2 authentication backend for teams"""

    name = "github-team"
    title = "GitHub Team"
    icon = "github.svg"
    no_member_string = "User doesn't belong to the team"

    def member_url(self, user_data):
        return urljoin(
            self.api_url(),
            f"teams/{self.setting('ID')}/members/{user_data.get('login')}",
        )


class GithubAppAuth(GithubOAuth2):
    """GitHub App OAuth authentication backend.

    App installation callback parameters are untrusted. Stateless installation
    callbacks restart OAuth so an authorization code is only exchanged after
    validating session-bound state.
    """

    name = "github-app"
    title = "GitHub App"
    icon = "github.svg"

    def auth_complete(self, *args, **kwargs):
        if not self.get_request_state() and all(
            self.data.get(name) for name in ("code", "installation_id", "setup_action")
        ):
            self.process_error(self.data)
            return self.start()

        return super().auth_complete(*args, **kwargs)
