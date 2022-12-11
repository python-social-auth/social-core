from unittest import TestCase

from django.contrib.auth import authenticate, login

# from django.contrib.auth.models import User
from django.shortcuts import redirect
from django_user import settings

from ...backends.casdoor import CasdoorSDK, User


class TestCasdoorAuth(TestCase):
    """
    You should replace the code content below and
    the get_sdk() method's content with your own Casdoor
    instance and such if you need to. And running these tests successfully
    proves that your connection to Casdoor is good-and-working!
    """

    backend_path = "social_core.backends.casdoor"

    # server returned authorization code
    code = "f97ae47cf361047eb7a8"

    @staticmethod
    def get_sdk():
        conf = settings.CASDOOR_CONFIG

        certificate = """-----BEGIN CERTIFICATE-----
        MIIE+TCCAuGgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMDYxHTAbBgNVBAoTFENh
        c2Rvb3IgT3JnYW5pemF0aW9uMRUwEwYDVQQDEwxDYXNkb29yIENlcnQwHhcNMjEx
        MDE1MDgxMTUyWhcNNDExMDE1MDgxMTUyWjA2MR0wGwYDVQQKExRDYXNkb29yIE9y
        Z2FuaXphdGlvbjEVMBMGA1UEAxMMQ2FzZG9vciBDZXJ0MIICIjANBgkqhkiG9w0B
        AQEFAAOCAg8AMIICCgKCAgEAsInpb5E1/ym0f1RfSDSSE8IR7y+lw+RJjI74e5ej
        rq4b8zMYk7HeHCyZr/hmNEwEVXnhXu1P0mBeQ5ypp/QGo8vgEmjAETNmzkI1NjOQ
        CjCYwUrasO/f/MnI1C0j13vx6mV1kHZjSrKsMhYY1vaxTEP3+VB8Hjg3MHFWrb07
        uvFMCJe5W8+0rKErZCKTR8+9VB3janeBz//zQePFVh79bFZate/hLirPK0Go9P1g
        OvwIoC1A3sarHTP4Qm/LQRt0rHqZFybdySpyWAQvhNaDFE7mTstRSBb/wUjNCUBD
        PTSLVjC04WllSf6Nkfx0Z7KvmbPstSj+btvcqsvRAGtvdsB9h62Kptjs1Yn7GAuo
        I3qt/4zoKbiURYxkQJXIvwCQsEftUuk5ew5zuPSlDRLoLByQTLbx0JqLAFNfW3g/
        pzSDjgd/60d6HTmvbZni4SmjdyFhXCDb1Kn7N+xTojnfaNkwep2REV+RMc0fx4Gu
        hRsnLsmkmUDeyIZ9aBL9oj11YEQfM2JZEq+RVtUx+wB4y8K/tD1bcY+IfnG5rBpw
        IDpS262boq4SRSvb3Z7bB0w4ZxvOfJ/1VLoRftjPbLIf0bhfr/AeZMHpIKOXvfz4
        yE+hqzi68wdF0VR9xYc/RbSAf7323OsjYnjjEgInUtRohnRgCpjIk/Mt2Kt84Kb0
        wn8CAwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAn2lf
        DKkLX+F1vKRO/5gJ+Plr8P5NKuQkmwH97b8CS2gS1phDyNgIc4/LSdzuf4Awe6ve
        C06lVdWSIis8UPUPdjmT2uMPSNjwLxG3QsrimMURNwFlLTfRem/heJe0Zgur9J1M
        8haawdSdJjH2RgmFoDeE2r8NVRfhbR8KnCO1ddTJKuS1N0/irHz21W4jt4rxzCvl
        2nR42Fybap3O/g2JXMhNNROwZmNjgpsF7XVENCSuFO1jTywLaqjuXCg54IL7XVLG
        omKNNNcc8h1FCeKj/nnbGMhodnFWKDTsJcbNmcOPNHo6ixzqMy/Hqc+mWYv7maAG
        Jtevs3qgMZ8F9Qzr3HpUc6R3ZYYWDY/xxPisuKftOPZgtH979XC4mdf0WPnOBLqL
        2DJ1zaBmjiGJolvb7XNVKcUfDXYw85ZTZQ5b9clI4e+6bmyWqQItlwt+Ati/uFEV
        XzCj70B4lALX6xau1kLEpV9O1GERizYRz5P9NJNA7KoO5AVMp9w0DQTkt+LbXnZE
        HHnWKy8xHQKZF9sR7YBPGLs/Ac6tviv5Ua15OgJ/8dLRZ/veyFfGo2yZsI+hKVU5
        nCCJHBcAyFnm1hdvdwEdH33jDBjNB6ciotJZrf/3VYaIWSalADosHAgMWfXuWP+h
        8XKXmzlxuHbTMQYtZPDgspS5aK+S4Q9wb8RRAYo=
        -----END CERTIFICATE-----
        """

        sdk = CasdoorSDK(
            endpoint="http://localhost:8000",
            client_id="fdb3972770f53a59b29a",
            client_secret="ab45c886ca7863c7cdccc7ace2d05a9ec08f1819",
            certificate=certificate,
            org_name="built-in",
            application_name="app-built-in",
        )

        return sdk

    # def test_get_oauth_token(self):
    #     sdk = self.get_sdk()
    #     access_token = sdk.get_oauth_token(self.code)
    #     self.assertIsInstance(access_token, str)
    #
    # def test_parse_jwt_token(self):
    #     sdk = self.get_sdk()
    #     access_token = sdk.get_oauth_token(self.code)
    #     decoded_msg = sdk.parse_jwt_token(access_token)
    #     self.assertIsInstance(decoded_msg, dict)

    def test_get_users(self):
        sdk = self.get_sdk()
        users = sdk.get_users()
        self.assertIsInstance(users, list)

    def test_get_user(self):
        sdk = self.get_sdk()
        user = sdk.get_user("admin")
        self.assertIsInstance(user, dict)

    def test_modify_user(self):
        sdk = self.get_sdk()
        user = User()
        user.name = "test_ffyuanda"
        sdk.delete_user(user)

        response = sdk.add_user(user)
        self.assertEqual(response["data"], "Affected")

        response = sdk.delete_user(user)
        self.assertEqual(response["data"], "Affected")

        response = sdk.add_user(user)
        self.assertEqual(response["data"], "Affected")

        user.phone = "phone"
        response = sdk.update_user(user)
        self.assertEqual(response["data"], "Affected")

        self.assertIn("status", response)
        self.assertIsInstance(response, dict)
