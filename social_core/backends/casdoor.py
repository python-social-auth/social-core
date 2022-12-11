import json

# from .user import User
from typing import List

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from django.apps import AppConfig
from django_user import settings


class User:
    def __init__(self):
        self.address = ["string"]
        self.affiliation = "string"
        self.avatar = "string"
        self.createdTime = "string"
        self.dingtalk = "string"
        self.displayName = "string"
        self.email = "string"
        self.facebook = "string"
        self.gitee = "string"
        self.github = "string"
        self.google = "string"
        self.hash = "string"
        self.id = "string"
        self.isAdmin = True
        self.isForbidden = True
        self.isGlobalAdmin = True
        self.language = "string"
        self.name = "string"
        self.owner = "string"
        self.password = "string"
        self.phone = "string"
        self.preHash = "string"
        self.qq = "string"
        self.score = 0
        self.signupApplication = "string"
        self.tag = "string"
        self.type = "string"
        self.updatedTime = "string"
        self.wechat = "string"
        self.weibo = "string"

    def __str__(self):
        return str(self.__dict__)

    def to_dict(self) -> dict:
        return self.__dict__


class CasdoorSDK:
    name = "casdoor"

    def __init__(
        self,
        endpoint: str,
        client_id: str,
        client_secret: str,
        certificate: str,
        org_name: str,
        application_name: str,
        front_endpoint: str = None,
    ):
        self.endpoint = endpoint
        if front_endpoint:
            self.front_endpoint = front_endpoint
        else:
            self.front_endpoint = endpoint.replace(":8000", ":7001")
        self.client_id = client_id
        self.client_secret = client_secret
        self.certificate = certificate
        self.org_name = org_name
        self.application_name = application_name
        self.grant_type = "authorization_code"

        self.algorithms = ["RS256"]

    @property
    def certification(self) -> bytes:
        if type(self.certificate) is not str:
            raise TypeError("certificate field must be str type")
        return self.certificate.encode("utf-8")

    def get_auth_link(
        self, redirect_uri: str, response_type: str = "code", scope: str = "read"
    ):
        url = self.front_endpoint + "/login/oauth/authorize"
        params = {
            "client_id": self.client_id,
            "response_type": response_type,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": self.application_name,
        }
        r = requests.request("", url, params=params)
        return r.url

    def get_oauth_token(self, code: str) -> str:
        """
        Request the Casdoor server to get access_token.
        :param code: the code that sent from Casdoor using redirect url back to your server.
        :return: access_token
        """
        url = self.endpoint + "/api/login/oauth/access_token"
        params = {
            "grant_type": self.grant_type,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
        }
        r = requests.post(url, params)
        access_token = r.json().get("access_token")

        return access_token

    def parse_jwt_token(self, token: str) -> dict:
        """
        Converts the returned access_token to real data using jwt (JSON Web Token) algorithms.
        :param token: access_token
        :return: the data in dict format
        """
        certificate = x509.load_pem_x509_certificate(
            self.certification, default_backend()
        )

        return_json = jwt.decode(
            token,
            certificate.public_key(),
            algorithms=self.algorithms,
            audience=self.client_id,
        )
        return return_json

    def get_users(self) -> List[dict]:
        """
        Get the users from Casdoor.
        :return: a list of dicts containing user info
        """
        url = self.endpoint + "/api/get-users"
        params = {
            "owner": self.org_name,
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        }
        r = requests.get(url, params)
        users = r.json()
        return users

    def get_user(self, user_id: str) -> dict:
        """
        Get the user from Casdoor providing the user_id.
        :param user_id: the id of the user
        :return: a dict that contains user's info
        """
        url = self.endpoint + "/api/get-user"
        params = {
            "id": f"{self.org_name}/{user_id}",
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        }
        r = requests.get(url, params)
        user = r.json()
        return user

    def modify_user(self, method: str, user: User) -> dict:
        url = self.endpoint + f"/api/{method}"
        user.owner = self.org_name
        params = {
            "id": f"{user.owner}/{user.name}",
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        }
        user_info = json.dumps(user.to_dict())
        r = requests.post(url, params=params, data=user_info)
        response = r.json()
        return response

    def add_user(self, user: User) -> dict:
        response = self.modify_user("add-user", user)
        return response

    def update_user(self, user: User) -> dict:
        response = self.modify_user("update-user", user)
        return response

    def delete_user(self, user: User) -> dict:
        response = self.modify_user("delete-user", user)
        return response


# class CasdoorAuth(AppConfig):
#     default_auto_field = "django.db.models.BigAutoField"
#     name = "social_core"
#
#     conf = settings.CASDOOR_CONFIG
#
#     sdk = CasdoorSDK(conf.get('endpoint'),
#                      conf.get('client_id'),
#                      conf.get('client_secret'),
#                      conf.get('certificate'),
#                      conf.get('org_name'),
#                      conf.get('application_name'),
#                      conf.get('endpoint'))
#
#     def get_users(self):
#         return self.sdk.get_users()
#
#     def get_user(self, request):
#         return self.sdk.get_user(request.GET.get('name'))
#
#     def add_user(self, request):
#         user = request.GET.get("name")
#         return self.sdk.add_user(user)
#
#     def update_user(self, request):
#         return self.sdk.add_user(request.GET.get('user'))
#
#     def delete_user(self, request):
#         return self.sdk.delete_user(request.GET.get('name'))
