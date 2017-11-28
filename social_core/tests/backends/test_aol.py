#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime

from httpretty import HTTPretty
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.message import Message
from social_core.exceptions import AuthMissingParameter
from social_core.tests.backends.open_id import OpenIdTest

from six.moves.urllib_parse import urlencode

# noinspection SpellCheckingInspection
JANRAIN_NONCE = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')


class AolOpenIdTest(OpenIdTest):
    backend_path = 'social_core.backends.aol.AOLOpenId'
    expected_username = 'foobar'
    html_body = ('\n'
                 '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd"><html><head><link rel="openid.server" '
                 'href="https://api.screenname.aol.com/auth/openidServer"/><link rel="openid2.provider" '
                 'href="https://api.screenname.aol.com/auth/openidServer"/><meta http-equiv="Content-Type" '
                 'content="text/html; charset=UTF-8"><title>AOL OpenId</title><meta http-equiv="refresh" '
                 'content="0;url=https://api.screenname.aol.com/auth/openid/name/{0}"></head><body>If '
                 'not redirected automatically, please click <a '
                 'href="https://api.screenname.aol.com/auth/openid/name/{0}">here</a> to '
                 'continue</body></html>').format(expected_username)
    # The protocol HTTPS in the URLs https://api.screenname.aol.com/auth/openidServer from the XRDS changed to HTTP.
    # Due to HTTPretty doesn't support HTTPS requests via the `requests` package, which is used in the
    # OpenIdTest.do_start()
    discovery_body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                      '\n'
                      '\n'
                      '\n'
                      '\n'
                      '\n'
                      '\n'
                      '<xrds:XRDS \n'
                      '    xmlns:xrds="xri://$xrds" \n'
                      '    xmlns:openid="http://openid.net/xmlns/1.0" \n'
                      '    xmlns="xri://$xrd*($v*2.0)"> \n'
                      '  <XRD> \n'
                      '   \n'
                      '   <Service priority="0"> \n'
                      '      <Type>http://specs.openid.net/auth/2.0/signon</Type> \n'
                      '      <Type>http://openid.net/extensions/sreg/1.1</Type>\n'
                      '      <Type>http://openid.net/srv/ax/1.0</Type>\n'
                      '      <Type>http://specs.openid.net/extensions/pape/1.0</Type>\n'
                      '      <Type>http://specs.openid.net/extensions/ui/1.0/mode/popup</Type>\n'
                      '      <Type>http://specs.openid.net/auth/2.0/httpMapping</Type>\n'
                      '<Type>http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier</Type>\n '
                      '      <Type>http://www.idmanagement.gov/schema/2009/05/icam/no-pii.pdf</Type>\n'
                      '      <Type>http://www.idmanagement.gov/schema/2009/05/icam/openid-trust-level1.pdf</Type>\n'
                      '      <Type>http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf</Type>\n'
                      '      <URI>http://api.screenname.aol.com/auth/openidServer</URI> \n'
                      '    </Service>\n'
                      '    \n'
                      '    <Service priority="1"> \n'
                      '     <Type>http://openid.net/signon/1.0</Type>\n'
                      '      <Type>http://openid.net/extensions/sreg/1.1</Type> \n'
                      '      <URI>http://api.screenname.aol.com/auth/openidServer</URI> \n'
                      '    </Service> \n'
                      '    \n'
                      '    <Service>\n'
                      '      <Type>http://specs.openid.net/auth/2.0/httpMapping</Type>\n'
                      '      <URI>http://openid.aol.com/{0}</URI>\n'
                      '    </Service>\n'
                      '    \n'
                      '  </XRD> \n'
                      '</xrds:XRDS>\n'.format(expected_username))
    assoc_type = 'HMAC-SHA1'
    # noinspection SpellCheckingInspection
    server_bml_body = ('ns:http://specs.openid.net/auth/2.0\n'
                       'session_type:DH-SHA1\n'
                       'assoc_type:{0}\n'
                       'assoc_handle:070b88acd1e911e788ab00163ef648a2\n'
                       'expires_in:86398\n'
                       'dh_server_public:NSDzJJsbLWNvpNYsHlILgobqbS2uSZKBIa1kggEy0RUB4sotwNH6TFnMMGhGHEb3p9fvidDwxCN'
                       '+99Zej3mXasnXzNWSm0OV5nBuRIhOPK4b4oj0yM8gcJbhnbeIPmkvysbmv3+RjK6WxqogcfeWOhiFBNcIqdnQ'
                       '+izWL2DBmFY=\n'
                       'enc_mac_key:us/oHtLai2hwW2SD57qX522O/g4=\n').format(assoc_type)
    # noinspection SpellCheckingInspection
    server_response_dict = {
        'janrain_nonce': JANRAIN_NONCE,
        'openid.mode': 'id_res',
        'openid.claimed_id': 'http://openid.aol.com/{0}'.format(expected_username),
        'openid.identity': 'http://openid.aol.com/{0}'.format(expected_username),
        'openid.return_to': 'http://myapp.com/complete/aol/?janrain_nonce={0}'.format(JANRAIN_NONCE),
        'openid.assoc_handle': '070b88acd1e911e788ab00163ef648a2',
        'openid.signed': 'return_to,identity'
    }

    # This method defined here because at first requested HTML, and only then from HTTP Header extracted this URL,
    # requested, and then XRDS responded
    def openid_url(self):
        return 'https://api.screenname.aol.com/auth/openid/xrds?id={0}'.format(self.expected_username)

    # This method copied from the LiveJournalOpenIdTest.post_start(). It is an error without it
    def post_start(self):
        self.strategy.remove_from_request_data('openid_aol_user')

    def _setup_handlers(self):
        open_id_server_url = 'http://api.screenname.aol.com/auth/openidServer'

        # The protocol HTTPS in the URL https://api.screenname.aol.com/auth/openidServer changed to HTTP. Due to
        # HTTPretty doesn't support HTTPS requests via the `requests` package, which is used in the
        # OpenIdTest.do_start()
        HTTPretty.register_uri(
            HTTPretty.POST,
            open_id_server_url,
            status=200,
            body=self.server_bml_body
        )

        # Calculating sig
        consumer = self.backend.consumer()
        endpoint = OpenIDServiceEndpoint()
        endpoint.server_url = open_id_server_url
        # noinspection PyProtectedMember
        assoc = consumer.consumer._getAssociation(endpoint)
        message_response = Message.fromPostArgs(self.server_response_dict)
        calculated_sig = assoc.getMessageSignature(message_response).decode('utf-8')
        self.server_response_dict['openid.sig'] = calculated_sig
        self.server_response = urlencode(self.server_response_dict)

        HTTPretty.register_uri(
            HTTPretty.GET,
            self.backend.openid_url(),
            adding_headers={
                'Content-Type': 'text/html; charset=utf-8',
                'X-XRDS-Location': 'https://api.screenname.aol.com/auth/openid/xrds?id={0}'.format(
                    self.expected_username),
            },
            status=200,
            body=self.html_body
        )

    def test_login(self):
        self.strategy.set_request_data({'openid_aol_user': self.expected_username}, self.backend)
        self._setup_handlers()
        self.do_login()

    # This test written according to corresponding test for from LiveJournalOpenIdTest. For AOL this test failed.
    # I suppose it is due to some issues in the OpenID response messages on the AOL side
    def test_partial_pipeline(self):
        self.strategy.set_request_data({'openid_aol_user': self.expected_username}, self.backend)
        self._setup_handlers()
        self.do_partial_pipeline()

    def test_failed_login(self):
        with self.assertRaises(AuthMissingParameter):
            self._setup_handlers()
        with self.assertRaises(AuthMissingParameter):
            self.do_login()
