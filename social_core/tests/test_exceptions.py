import unittest

from social_core.backends.base import BaseAuth
from social_core.exceptions import (
    AuthAlreadyAssociated,
    AuthCanceled,
    AuthException,
    AuthFailed,
    AuthForbidden,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
    AuthTokenError,
    AuthTokenRevoked,
    AuthUnknownError,
    AuthUnreachableProvider,
    InvalidEmail,
    MissingBackend,
    NotAllowedToDisconnect,
    SocialAuthBaseException,
    WrongBackend,
)

from .models import TestStorage
from .strategy import TestStrategy


class BaseExceptionTestCase(unittest.TestCase):
    exception: SocialAuthBaseException = SocialAuthBaseException("base test")
    expected_message: str = "base test"

    def test_exception_message(self) -> None:
        try:
            raise self.exception
        except SocialAuthBaseException as err:
            self.assertEqual(str(err), self.expected_message)


class WrongBackendTest(BaseExceptionTestCase):
    exception = WrongBackend("foobar")
    expected_message = 'Incorrect authentication service "foobar"'


class AuthFailedTest(BaseExceptionTestCase):
    exception = AuthFailed(BaseAuth(TestStrategy(TestStorage)), "wrong_user")
    expected_message = "Authentication failed: wrong_user"


class AuthFailedDeniedTest(BaseExceptionTestCase):
    exception = AuthFailed(BaseAuth(TestStrategy(TestStorage)), "access_denied")
    expected_message = "Authentication process was canceled"


class AuthTokenErrorTest(BaseExceptionTestCase):
    exception = AuthTokenError(BaseAuth(TestStrategy(TestStorage)), "Incorrect tokens")
    expected_message = "Token error: Incorrect tokens"


class AuthMissingParameterTest(BaseExceptionTestCase):
    exception = AuthMissingParameter(BaseAuth(TestStrategy(TestStorage)), "username")
    expected_message = "Missing needed parameter username"


class AuthStateMissingTest(BaseExceptionTestCase):
    exception = AuthStateMissing(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "Session value state missing."


class NotAllowedToDisconnectTest(BaseExceptionTestCase):
    exception = NotAllowedToDisconnect()
    expected_message = "This account is not allowed to be disconnected."


class AuthExceptionTest(BaseExceptionTestCase):
    exception = AuthException(BaseAuth(TestStrategy(TestStorage)), "message")
    expected_message = "message"


class AuthCanceledTest(BaseExceptionTestCase):
    exception = AuthCanceled(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "Authentication process canceled"


class AuthCanceledWithExtraMessageTest(BaseExceptionTestCase):
    exception = AuthCanceled(BaseAuth(TestStrategy(TestStorage)), "error_message")
    expected_message = "Authentication process canceled: error_message"


class AuthUnknownErrorTest(BaseExceptionTestCase):
    exception = AuthUnknownError(BaseAuth(TestStrategy(TestStorage)), "some error")
    expected_message = "An unknown error happened while authenticating some error"


class AuthStateForbiddenTest(BaseExceptionTestCase):
    exception = AuthStateForbidden(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "Wrong state parameter given."


class AuthAlreadyAssociatedTest(BaseExceptionTestCase):
    exception = AuthAlreadyAssociated(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "This account is already in use."


class AuthTokenRevokedTest(BaseExceptionTestCase):
    exception = AuthTokenRevoked(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "User revoke access to the token"


class AuthForbiddenTest(BaseExceptionTestCase):
    exception = AuthForbidden(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "Your credentials aren't allowed"


class AuthUnreachableProviderTest(BaseExceptionTestCase):
    exception = AuthUnreachableProvider(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "The authentication provider could not be reached"


class InvalidEmailTest(BaseExceptionTestCase):
    exception = InvalidEmail(BaseAuth(TestStrategy(TestStorage)))
    expected_message = "Email couldn't be validated"


class MissingBackendTest(BaseExceptionTestCase):
    exception = MissingBackend("backend")
    expected_message = 'Missing backend "backend" entry'
