import json

from .oauth import OAuth2Test

from social_core.backends.orcid import ORCIDOAuth2

class ORCIDOAuth2Test(OAuth2Test):
    backend_path = 'social_core.backends.orcid.ORCIDOAuth2'
    user_data_url = 'https://login.orbi.kr/oauth/user/get'
    expected_username = 'foobar'
    access_token_body = json.dumps({
        'access_token': 'foobar',
    })
    user_data_body = json.dumps({
        "sub":"0000-0002-2601-8132",
        "name":"Credit Name",
        "family_name":"Jones",
        "given_name":"Tom"
    })

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
