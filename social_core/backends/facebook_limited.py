"""
Facebook Limited Login backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/facebook.html
"""

from typing import Any

from social_core.exceptions import AuthResponseError

from .open_id_connect import OpenIdConnectAuth


class FacebookLimitedLogin(OpenIdConnectAuth):
    """Facebook Limited Login (OIDC) backend"""

    name = "facebook-limited-login"
    title = "Facebook"
    icon = "facebook.svg"
    OIDC_ENDPOINT = "https://www.facebook.com"
    ACCESS_TOKEN_URL = "https://facebook.com/dialog/oauth/"
    ID_TOKEN_MAX_AGE = 3600
    _partial_pipeline_resume = False

    def authenticate(self, *args, **kwargs):
        if (
            "backend" not in kwargs
            or kwargs["backend"].name != self.name
            or "strategy" not in kwargs
            or "response" not in kwargs
        ):
            return None

        # Only continue_pipeline() may authorize reuse of restored claims.
        # Consume that authorization before entering any pipeline steps.
        partial_resume = self._partial_pipeline_resume
        self._partial_pipeline_resume = False
        if (
            not partial_resume
            or self.id_token is None
            or "access_token" in kwargs["response"]
        ):
            raw_jwt = kwargs.get("response", {}).get("access_token")
            if not raw_jwt:
                raise AuthResponseError(
                    self, "Missing access_token", code="missing_claim", stage="callback"
                )
            self.id_token = self.validate_and_return_id_token(raw_jwt, "")
        kwargs["response"] = self.id_token.copy()
        return super().authenticate(*args, **kwargs)

    def continue_pipeline(self, partial):
        # The OIDC parent restores claims from trusted partial storage before
        # invoking authenticate(). Never leave resume authorization behind.
        self._partial_pipeline_resume = True
        try:
            return super().continue_pipeline(partial)
        finally:
            self._partial_pipeline_resume = False

    def get_user_details(self, response):
        return {
            "fullname": response.get("name"),
            "email": response.get("email"),
            "picture": response.get("picture"),
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        # We don't have an access token to call any API for the user details.
        return {}

    def validate_claims(self, id_token) -> None:
        try:
            super().validate_claims(id_token)
        except AuthResponseError as e:
            if e.code == "nonce_mismatch":
                # Ignore errors about nonce. We can't validate it since it's not generated server-side.
                return
            raise
