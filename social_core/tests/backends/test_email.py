from .legacy import BaseLegacyTest


class EmailTest(BaseLegacyTest):
    backend_path = "social_core.backends.email.EmailAuth"
    expected_username = "foo"
    response_body = "email=foo@bar.com"
    form = """
    <form method="post" action="{0}">
        <input name="email" type="text">
        <button>Submit</button>
    </form>
    """

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
