"""Assertions for the stable authentication failure contract."""

from contextlib import contextmanager


@contextmanager
def assert_auth_error(test, exception_type, code):
    with test.assertRaises(exception_type) as caught:
        yield caught
    test.assertEqual(caught.exception.code, code)
