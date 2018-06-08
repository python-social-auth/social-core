import json

from .oauth import OAuth2Test


class IntercomOAuth2Test(OAuth2Test):
    backend_path = 'social_core.backends.intercom.IntercomOAuth2'
    user_data_url = 'https://api.intercom.io/me'
    expected_username = 'foo@bar.com'
    access_token_body = json.dumps({
        'access_token': 'foobar',
        'token_type': 'bearer'
    })
    # https://developers.intercom.com/v2.0/reference#admins
    user_data_body = json.dumps({
        'data': {
            "type": "admin",
            "id": "123456",
            "email": "foo@bbar.com",
            "name": "Foo Bar",
            "email_verified": true,
            "app": {
                "type": "app",
                "id_code": "123456",
                "name": "Foo Bar",
                "created_at": 0,
                "secure": false,
                "identity_verification": false,
                "timezone": "America/Los_Angeles"
            },
            "avatar": {
                "type": "avatar",
                "image_url": ""
            }
        }
    })

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
