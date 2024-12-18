from .oauth import BaseOAuth2PKCE


class EtsyOAuth2(BaseOAuth2PKCE):
    name = "etsy"
    ID_KEY = "user_id"
    AUTHORIZATION_URL = "https://www.etsy.com/oauth/connect"
    ACCESS_TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"
    REFRESH_TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    ACCESS_TOKEN_METHOD = "POST"
    REQUEST_TOKEN_METHOD = "POST"
    SCOPE_SEPARATOR = " "
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("refresh_token", "refresh_token"),
        ("expires_in", "expires_in"),
        ("token_type", "token_type"),
        ("access_token", "access_token"),
        # User Data Fields
        ("primary_email", "primary_email"),
        ("first_name", "first_name"),
        ("last_name", "last_name"),
        ("image_url_75x75", "image_url_75x75"),
    ]

    def user_data(self, access_token, *args, **kwargs) -> dict:
        client_id, _ = self.get_key_and_secret()
        user_id = access_token.split(".")[0]
        headers = {"Authorization": f"Bearer {access_token}", "x-api-key": client_id}
        return self.get_json(
            url=f"https://openapi.etsy.com/v3/application/users/{user_id}",
            headers=headers,
        )

    def get_user_details(self, response):
        return {
            "user_id": response["user_id"],
            "first_name": response["first_name"],
            "last_name": response["last_name"],
            "email": response["primary_email"],
            "image_url_75x75": response["image_url_75x75"],
            "username": str(response["user_id"]),
        }
