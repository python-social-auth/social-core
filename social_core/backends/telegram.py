from __future__ import annotations

import hashlib
import hmac
import time
from typing import TYPE_CHECKING, Any

from social_core.exceptions import (
    AuthConfigurationError,
    AuthInputError,
    AuthResponseError,
)
from social_core.utils import handle_http_errors

from .base import BaseAuth

if TYPE_CHECKING:
    from social_core.storage import UserProtocol
    from social_core.strategy import HttpResponseProtocol


class TelegramAuth(BaseAuth):
    name = "telegram"
    title = "Telegram"
    ID_KEY = "id"

    def verify_data(self, response) -> None:
        bot_token = self.setting("BOT_TOKEN")
        if bot_token is None:
            raise AuthConfigurationError(
                self,
                parameter="SOCIAL_AUTH_TELEGRAM_BOT_TOKEN",
                code="missing_setting",
                stage="callback",
            )

        received_hash_string = response.get("hash")
        auth_date = response.get("auth_date")

        if received_hash_string is None or auth_date is None:
            raise AuthInputError(
                self,
                parameter="hash or auth_date",
                code="missing_parameter",
                stage="callback",
            )

        data_check_lines = [f"{k}={v}" for k, v in response.items() if k != "hash"]
        data_check_string = "\n".join(sorted(data_check_lines))
        secret_key = hashlib.sha256(bot_token.encode()).digest()
        built_hash = hmac.new(
            secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256
        ).hexdigest()
        current_timestamp = int(time.time())
        if not isinstance(auth_date, (str, int)) or isinstance(auth_date, bool):
            raise AuthInputError(
                self, parameter="auth_date", code="invalid_parameter", stage="callback"
            )
        try:
            auth_timestamp = int(auth_date)
        except (ValueError, TypeError) as error:
            raise AuthInputError(
                self, parameter="auth_date", code="invalid_parameter", stage="callback"
            ) from error
        if current_timestamp - auth_timestamp > 86400:
            raise AuthResponseError(
                self, "Auth date is outdated", code="response_expired", stage="callback"
            )
        if built_hash != received_hash_string:
            raise AuthResponseError(
                self,
                "Invalid hash supplied",
                code="invalid_signature",
                stage="callback",
            )

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        return response

    def get_user_details(self, response):
        first_name = response.get("first_name", "")
        last_name = response.get("last_name", "")
        return {
            "username": response.get("username") or str(response[self.id_key()]),
            "first_name": first_name,
            "last_name": last_name,
            "fullname": "",
        }

    @handle_http_errors
    def auth_complete(
        self, *args, **kwargs
    ) -> HttpResponseProtocol | UserProtocol | None:
        response = self.data
        self.verify_data(response)
        kwargs.update({"response": self.data, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)
