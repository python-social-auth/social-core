"""
Github Enterprise OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/github_enterprise.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from urllib.parse import urljoin

from social_core.exceptions import AuthMissingParameter
from social_core.utils import append_slash

from .github import GithubOAuth2, GithubOrganizationOAuth2, GithubTeamOAuth2

if TYPE_CHECKING:
    from .base import BaseAuth


class GithubEnterpriseMixin:
    def _required_setting(self, name: str) -> str:
        value = cast("GithubOAuth2", self).setting(name)
        if not value:
            raise AuthMissingParameter(cast("BaseAuth", self), name)
        return cast("str", value)

    def api_url(self):
        return append_slash(self._required_setting("API_URL"))

    def authorization_url(self):
        return self._url("login/oauth/authorize")

    def access_token_url(self):
        return self._url("login/oauth/access_token")

    def _url(self, path):
        return urljoin(append_slash(self._required_setting("URL")), path)


class GithubEnterpriseOAuth2(GithubEnterpriseMixin, GithubOAuth2):
    """Github Enterprise OAuth authentication backend"""

    name = "github-enterprise"


class GithubEnterpriseOrganizationOAuth2(
    GithubEnterpriseMixin, GithubOrganizationOAuth2
):
    """Github Enterprise OAuth2 authentication backend for
    organizations"""

    name = "github-enterprise-org"
    DEFAULT_SCOPE = ["read:org"]


class GithubEnterpriseTeamOAuth2(GithubEnterpriseMixin, GithubTeamOAuth2):
    """Github Enterprise OAuth2 authentication backend for teams"""

    name = "github-enterprise-team"
    DEFAULT_SCOPE = ["read:org"]
