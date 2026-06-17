"""
Backend for SAML 2.0 support

Terminology:

"Service Provider" (SP): Your web app
"Identity Provider" (IdP): The third-party site that is authenticating
                           users via SAML
"""

from __future__ import annotations

import json
from binascii import Error as BinasciiError
from typing import Any, cast

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from social_core.exceptions import (
    AuthFailed,
    AuthInvalidParameter,
    AuthMissingParameter,
)
from social_core.utils import constant_time_compare, user_is_authenticated

from .base import BaseAuth

# Helpful constants:
OID_COMMON_NAME = "urn:oid:2.5.4.3"
OID_EDU_PERSON_PRINCIPAL_NAME = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
OID_EDU_PERSON_ENTITLEMENT = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
OID_GIVEN_NAME = "urn:oid:2.5.4.42"
OID_MAIL = "urn:oid:0.9.2342.19200300.100.1.3"
OID_SURNAME = "urn:oid:2.5.4.4"
OID_USERID = "urn:oid:0.9.2342.19200300.100.1.1"


FULLNAME_FIELDS = (
    OID_COMMON_NAME,
    "http://schemas.xmlsoap.org/claims/CommonName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/fullname",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "full_name",
    "fullname",
    "fullName",
)

FIRST_NAME_FIELDS = (
    OID_GIVEN_NAME,
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "first_name",
    "firstname",
    "firstName",
    "given_name",
    "givenname",
    "givenName",
)
LAST_NAME_FIELDS = (
    OID_SURNAME,
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "last_name",
    "lastname",
    "lastName",
    "surname",
)
EMAIL_FIELDS = (
    OID_MAIL,
    "http://schemas.xmlsoap.org/claims/EmailAddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "email",
    "mail",
)

USERNAME_FIELDS = (
    OID_USERID,
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "subjectNameID",
    "username",
)

PERSISTENT_FIELDS = (
    OID_USERID,
    "name_id",
)


class SAMLIdentityProvider:
    """Wrapper around configuration for a SAML Identity provider"""

    def __init__(self, backend: BaseAuth, name: str, **kwargs) -> None:
        """Load and parse configuration"""
        self.backend: BaseAuth = backend
        self.name: str = name
        # name should be a slug and must not contain a colon, which
        # could conflict with uid prefixing:
        assert ":" not in self.name and " " not in self.name, (
            'IdP "name" should be a slug (short, no spaces)'
        )
        self.conf = kwargs

    def get_user_permanent_id(
        self, attributes: dict[str, str | list[str] | None]
    ) -> str:
        """
        The most important method: Get a permanent, unique identifier
        for this user from the attributes supplied by the IdP.

        If you want to use the NameID, it's available via
        attributes['name_id']
        """
        setting = "attr_user_permanent_id"
        uid = self.get_attr(attributes, setting, PERSISTENT_FIELDS)
        if not uid:
            raise AuthInvalidParameter(self.backend, "attr_user_permanent_id")
        return uid

    # Attributes processing:
    def get_user_details(
        self, attributes: dict[str, str | list[str] | None]
    ) -> dict[str, str | None]:
        """
        Given the SAML attributes extracted from the SSO response, get
        the user data like name.
        """
        return {
            "fullname": self.get_attr(attributes, "attr_full_name", FULLNAME_FIELDS),
            "first_name": self.get_attr(
                attributes, "attr_first_name", FIRST_NAME_FIELDS
            ),
            "last_name": self.get_attr(attributes, "attr_last_name", LAST_NAME_FIELDS),
            "username": self.get_attr(attributes, "attr_username", USERNAME_FIELDS),
            "email": self.get_attr(attributes, "attr_email", EMAIL_FIELDS),
        }

    def get_attr(
        self,
        attributes: dict[str, str | list[str] | None],
        conf_key: str,
        default_attributes: tuple[str, ...],
        *,
        validate_defaults: bool = False,
    ) -> str | None:
        """
        Internal helper method.
        Get the attribute 'default_attribute' out of the attributes,
        unless self.conf[conf_key] overrides the default by specifying
        another attribute to use.
        """
        validate = True

        try:
            # Use configured value
            attribute_name = self.conf[conf_key]
        except KeyError:
            # Find first matching attribute from default ones
            for attribute_name in default_attributes:
                if attribute_name in attributes:
                    break
            else:
                return None
            validate = validate_defaults
        else:
            # Value explicitly set to None, ignore the attribute
            if attribute_name is None:
                return None

        try:
            value = attributes[attribute_name]
        except KeyError as error:
            if validate:
                # Fail if configured or required attribute is not present
                raise AuthMissingParameter(
                    self.backend,
                    f"{attribute_name} (configured by {conf_key})",
                ) from error
            return None

        # Convert values list to the first value (if present)
        if isinstance(value, list):
            value = value[0] if value else None

        return value

    @property
    def entity_id(self):
        """Get the entity ID for this IdP"""
        # Required. e.g. "https://idp.testshib.org/idp/shibboleth"
        return self.conf["entity_id"]

    @property
    def sso_url(self):
        """Get the SSO URL for this IdP"""
        # Required. e.g.
        # "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO"
        return self.conf["url"]

    @property
    def slo_url(self):
        """Get the SLO URL for this IdP"""
        return self.conf.get("slo_url")

    @property
    def saml_config_dict(self):
        """Get the IdP configuration dict in the format required by
        python-saml"""
        result = {
            "entityId": self.entity_id,
            "singleSignOnService": {
                "url": self.sso_url,
                # python-saml only supports Redirect
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
        }

        if self.slo_url:
            result["singleLogoutService"] = {
                "url": self.slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }

        cert = self.conf.get("x509cert", None)
        if cert:
            result["x509cert"] = cert
            return result
        cert = self.conf.get("x509certMulti", None)
        if cert:
            result["x509certMulti"] = cert
            return result
        raise KeyError("IDP must contain x509cert or x509certMulti")


class SAMLAuth(BaseAuth):
    """
    PSA Backend that implements SAML 2.0 Service Provider (SP) functionality.

    Unlike all of the other backends, this one can be configured to work with
    many identity providers (IdPs). For example, a University that belongs to a
    Shibboleth federation may support authentication via ~100 partner
    universities. Also, the IdP configuration can be changed at runtime if you
    require that functionality - just subclass this and override `get_idp()`.

    Several settings are required. Here's an example:

    SOCIAL_AUTH_SAML_SP_ENTITY_ID = "https://saml.example.com/"
    SOCIAL_AUTH_SAML_SP_PUBLIC_CERT = "... X.509 certificate string ..."
    SOCIAL_AUTH_SAML_SP_PRIVATE_KEY = "... private key ..."
    SOCIAL_AUTH_SAML_ORG_INFO = {
        "en-US": {
            "name": "example",
            "displayname": "Example Inc.",
            "url": "http://example.com"
        }
    }
    SOCIAL_AUTH_SAML_TECHNICAL_CONTACT = {
        "givenName": "Tech Gal",
        "emailAddress": "technical@example.com"
    }
    SOCIAL_AUTH_SAML_SUPPORT_CONTACT = {
        "givenName": "Support Guy",
        "emailAddress": "support@example.com"
    }
    SOCIAL_AUTH_SAML_ENABLED_IDPS = {
        "testshib": {
            "entity_id": "https://idp.testshib.org/idp/shibboleth",
            "url": "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO",
            "x509cert": "MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0B...
                        ...8Bbnl+ev0peYzxFyF5sQA==",
        }
    }

    Optional settings:
    SOCIAL_AUTH_SAML_SP_EXTRA = {}
    SOCIAL_AUTH_SAML_SECURITY_CONFIG = {}
    """

    name = "saml"
    EXTRA_DATA = []

    def _authn_request_id_session_key(self, idp_name: str) -> str:
        return f"{self.name}_{idp_name}_authn_request_id"

    def _process_response(
        self, auth: OneLogin_Saml2_Auth, request_id: str | None = None
    ) -> None:
        try:
            auth.process_response(request_id=request_id)
        except OneLogin_Saml2_Error as error:
            raise AuthFailed(self, f"SAML login failed: {error}") from error
        errors = auth.get_errors()
        if errors or not auth.is_authenticated():
            reason = auth.get_last_error_reason()
            raise AuthFailed(self, f"SAML login failed: {errors} ({reason})")

    def _validate_in_response_to(
        self, auth: OneLogin_Saml2_Auth, request_id: str
    ) -> None:
        in_response_to = auth.get_last_response_in_response_to()
        if not in_response_to or not constant_time_compare(in_response_to, request_id):
            raise AuthFailed(self, "SAML login failed: invalid InResponseTo")

    def _response_in_response_to(self, idp: SAMLIdentityProvider) -> str | None:
        try:
            saml_response = self.strategy.request_post()["SAMLResponse"]
            response = OneLogin_Saml2_Response(
                OneLogin_Saml2_Settings(self.generate_saml_config(idp)),
                saml_response,
            )
        except (BinasciiError, KeyError, OneLogin_Saml2_Error, ValueError):
            return None
        return cast("str | None", response.get_in_response_to())

    def _request_id_required(
        self, request_id: str | None, kwargs: dict[str, Any]
    ) -> bool:
        return bool(request_id) or user_is_authenticated(kwargs.get("user"))

    def _check_missing_request_id(
        self, request_id: str | None, session_id: str | None, kwargs: dict[str, Any]
    ) -> None:
        if (
            self._request_id_required(request_id, kwargs)
            and not request_id
            and not session_id
        ):
            raise AuthFailed(self, "SAML login failed: missing AuthnRequest ID")

    def _validate_processed_response_request_id(
        self,
        auth: OneLogin_Saml2_Auth,
        request_id: str | None,
        kwargs: dict[str, Any],
    ) -> bool:
        get_in_response_to = getattr(auth, "get_last_response_in_response_to", None)
        in_response_to = get_in_response_to() if get_in_response_to else None
        if in_response_to:
            if not request_id:
                raise AuthFailed(self, "SAML login failed: missing AuthnRequest ID")
            self._validate_in_response_to(auth, request_id)
            return True
        if user_is_authenticated(kwargs.get("user")):
            raise AuthFailed(self, "SAML login failed: invalid InResponseTo")
        return False

    def _validate_auth_response(
        self,
        auth: OneLogin_Saml2_Auth,
        request_id_key: str,
        request_id: str | None,
        session_id: str | None,
        kwargs: dict[str, Any],
        response_in_response_to: str | None,
    ) -> tuple[bool, bool]:
        self._check_missing_request_id(request_id, session_id, kwargs)
        if session_id:
            if response_in_response_to:
                # Authenticate the SAML response before trusting RelayState to
                # restore another session. The restored request ID is checked
                # against this response below.
                self._process_response(auth, response_in_response_to)
                self.strategy.restore_session(session_id, kwargs)
                request_id = cast(
                    "str | None", self.strategy.session_get(request_id_key)
                )
                if not request_id:
                    raise AuthFailed(self, "SAML login failed: missing AuthnRequest ID")
            else:
                self._process_response(auth)
                self.strategy.restore_session(session_id, kwargs)
                request_id = cast(
                    "str | None", self.strategy.session_get(request_id_key)
                )
                return True, self._validate_processed_response_request_id(
                    auth, request_id, kwargs
                )
            self._validate_in_response_to(auth, request_id)
            return True, True
        if response_in_response_to:
            if not request_id:
                raise AuthFailed(self, "SAML login failed: missing AuthnRequest ID")
            self._process_response(auth, request_id)
            self._validate_in_response_to(auth, request_id)
            return False, True
        self._process_response(auth)
        return False, self._validate_processed_response_request_id(
            auth, request_id, kwargs
        )

    def get_idp(self, idp_name: str | None) -> SAMLIdentityProvider:
        """Given the name of an IdP, get a SAMLIdentityProvider instance"""
        enabled_idps: dict[str, dict] = cast(
            "dict[str, dict]", self.setting("ENABLED_IDPS")
        )
        if idp_name is None:
            # RelayState was missing, perhaps an IdP initiated flow
            if len(enabled_idps) != 1:
                raise AuthMissingParameter(self, "RelayState.idp")
            # Use the only configured IDP
            idp_name = next(iter(enabled_idps))
        idp_config = enabled_idps[idp_name]
        return SAMLIdentityProvider(self, idp_name, **idp_config)

    def generate_saml_config(self, idp: SAMLIdentityProvider | None = None):
        """
        Generate the configuration required to instantiate OneLogin_Saml2_Auth
        """
        # The shared absolute URL that all IdPs redirect back to -
        # this is specified in our metadata.xml:
        abs_completion_url = self.redirect_uri
        config = {
            "contactPerson": {
                "technical": self.setting("TECHNICAL_CONTACT"),
                "support": self.setting("SUPPORT_CONTACT"),
            },
            "debug": True,
            "idp": idp.saml_config_dict if idp else {},
            "organization": self.setting("ORG_INFO"),
            "security": {
                "metadataValidUntil": "",
                "metadataCacheDuration": "P10D",  # metadata valid for ten days
            },
            "sp": {
                "assertionConsumerService": {
                    "url": abs_completion_url,
                    # python-saml only supports HTTP-POST
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "entityId": self.setting("SP_ENTITY_ID"),
                "x509cert": self.setting("SP_PUBLIC_CERT"),
                "privateKey": self.setting("SP_PRIVATE_KEY"),
            },
            "strict": True,  # We must force strict mode - for security
        }
        cast("dict", config["security"]).update(
            cast("dict", self.setting("SECURITY_CONFIG", {}))
        )
        cast("dict", config["sp"]).update(cast("dict", self.setting("SP_EXTRA", {})))
        return config

    def generate_metadata_xml(self):
        """
        Helper method that can be used from your web app to generate the XML
        metadata required to link your web app as a Service Provider.

        Returns (metadata XML string, list of errors)

        Example usage (Django):
            from ..apps.django_app.utils import load_strategy, \
                                                     load_backend
            def saml_metadata_view(request):
                complete_url = reverse('social:complete', args=("saml", ))
                saml_backend = load_backend(load_strategy(request), "saml",
                                            complete_url)
                metadata, errors = saml_backend.generate_metadata_xml()
                if not errors:
                    return HttpResponse(content=metadata,
                                        content_type='text/xml')
                return HttpResponseServerError(content=', '.join(errors))
        """
        config = self.generate_saml_config()
        saml_settings = OneLogin_Saml2_Settings(config, sp_validation_only=True)
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        return metadata, errors

    def _create_saml_auth(self, idp: SAMLIdentityProvider):
        """Get an instance of OneLogin_Saml2_Auth"""
        config = self.generate_saml_config(idp)
        request_info = {
            "https": "on" if self.strategy.request_is_secure() else "off",
            "http_host": self.strategy.request_host(),
            "script_name": self.strategy.request_path(),
            "get_data": self.strategy.request_get(),
            "post_data": self.strategy.request_post(),
        }
        return OneLogin_Saml2_Auth(request_info, config)

    def auth_url(self):
        """Get the URL to which we must redirect in order to
        authenticate the user"""
        try:
            idp_name = self.strategy.request_data()["idp"]
        except KeyError as error:
            raise AuthMissingParameter(self, "idp") from error
        idp = self.get_idp(idp_name)
        auth = self._create_saml_auth(idp=idp)
        # Below, return_to sets the RelayState, which can contain
        # arbitrary data.  We use it to store the specific SAML IdP
        # name, since we multiple IdPs share the same auth_complete
        # URL, and the URL to redirect to after auth completes.
        relay_state = {
            "idp": idp_name,
            "next": self.data.get("next"),
        }
        if session_id := self.strategy.get_session_id():
            relay_state[self.strategy.SESSION_SAVE_KEY] = session_id
        url = auth.login(return_to=json.dumps(relay_state))
        self.strategy.session_set(
            self._authn_request_id_session_key(idp.name), auth.get_last_request_id()
        )
        return url

    def get_user_details(self, response):
        """Get user details like full name, email, etc. from the
        response - see auth_complete"""
        idp = self.get_idp(response["idp_name"])
        return idp.get_user_details(response["attributes"])

    def get_user_id(self, details, response) -> str:
        """
        Get the permanent ID for this user from the response.
        We prefix each ID with the name of the IdP so that we can
        connect multiple IdPs to this user.
        """
        idp = self.get_idp(response["idp_name"])
        uid = idp.get_user_permanent_id(response["attributes"])
        return f"{idp.name}:{uid}"

    def parse_relay_state(self, relay_state_str: str) -> dict:
        """Parse RelayState JSON or simple string into a dict"""
        try:
            relay_state: dict = json.loads(relay_state_str)
        except json.JSONDecodeError:
            # this is for backward compatibility; also some identity providers
            # (like Okta) send a simple string with the IdP name in RelayState
            # during IdP-initiated SSO:
            relay_state = {"idp": relay_state_str}

        # Validate that the data is dict
        if not isinstance(relay_state, dict):
            raise AuthInvalidParameter(self, "RelayState")

        return relay_state

    def auth_complete(self, *args, **kwargs):
        """
        The user has been redirected back from the IdP and we should
        now log them in, if everything checks out.
        """
        idp_name: str | None
        session_id: str | None = None
        next_url: str | None = None
        try:
            relay_state_str = self.strategy.request_data()["RelayState"]
        except KeyError:
            idp_name = None
        else:
            relay_state = self.parse_relay_state(relay_state_str)

            # Get IdP name
            idp_name = relay_state.get("idp")

            if not idp_name:
                raise AuthInvalidParameter(self, "RelayState.idp")

            session_id = relay_state.get(self.strategy.SESSION_SAVE_KEY)
            next_url = relay_state.get("next")

        idp = self.get_idp(idp_name)
        request_id_key = self._authn_request_id_session_key(idp.name)
        request_id = cast("str | None", self.strategy.session_get(request_id_key))
        if session_id:
            request_id = None
        self._check_missing_request_id(request_id, session_id, kwargs)
        response_in_response_to = self._response_in_response_to(idp)

        auth = self._create_saml_auth(idp)
        session_restored, request_id_validated = self._validate_auth_response(
            auth,
            request_id_key,
            request_id,
            session_id,
            kwargs,
            response_in_response_to,
        )
        if request_id_validated:
            self.strategy.session_pop(request_id_key)
        attributes = auth.get_attributes()
        attributes["name_id"] = auth.get_nameid()
        self._check_entitlements(idp, attributes)
        if session_id and not session_restored:
            self.strategy.restore_session(session_id, kwargs)
        elif next_url:
            # The do_complete action expects the "next" URL to be in
            # session state or the request params.
            self.strategy.session_set(kwargs.get("redirect_name", "next"), next_url)
        response = {
            "idp_name": idp_name,
            "attributes": attributes,
            "session_index": auth.get_session_index(),
        }
        kwargs.update({"response": response, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        extra_data = super().extra_data(
            user, uid, response["attributes"], details, pipeline_kwargs
        )
        extra_data["session_index"] = response["session_index"]
        extra_data["name_id"] = response["attributes"]["name_id"]
        return extra_data

    def request_logout(self, idp_name, social_auth, return_to=None):
        idp = self.get_idp(idp_name)
        auth = self._create_saml_auth(idp)
        name_id = social_auth.extra_data["name_id"]
        session_index = social_auth.extra_data["session_index"]
        return auth.logout(
            name_id=name_id, session_index=session_index, return_to=return_to
        )

    def process_logout(self, idp_name, delete_session_cb):
        idp = self.get_idp(idp_name)
        auth = self._create_saml_auth(idp)
        url = auth.process_slo(delete_session_cb=delete_session_cb)
        errors = auth.get_errors()
        return url, errors

    def _check_entitlements(self, idp, attributes) -> None:
        """
        Additional verification of a SAML response before
        authenticating the user.

        Subclasses can override this method if they need custom
        validation code, such as requiring the presence of an
        eduPersonEntitlement.

        raise social_core.exceptions.AuthForbidden if the user should not
        be authenticated, or do nothing to allow the login pipeline to
        continue.
        """
