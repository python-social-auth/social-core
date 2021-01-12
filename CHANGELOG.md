# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [4.0.3](https://github.com/python-social-auth/social-core/releases/tag/4.0.3) - 2021-01-12

### Changed
- Updated PyJWT version to 2.0.0
- Remove six dependency

## [4.0.2](https://github.com/python-social-auth/social-core/releases/tag/4.0.2) - 2021-01-10

### Changed
- Fixes to Github-action release mechanism

## [4.0.1](https://github.com/python-social-auth/social-core/releases/tag/4.0.1) - 2021-01-10

### Changed
- Fixes to Github-action release mechanism

## [4.0.0](https://github.com/python-social-auth/social-core/releases/tag/4.0.0) - 2021-01-10

### Added
- PayPal backend
- Fence OIDC-based backend

### Changed
- Dropped Python 2 support from testing stack
- Remove discontinued Google OpenId backend
- Remove discontinued Yahoo OpenId backend
- Fix `jwt.decode()` passed algorithm
- Prevent `PyJWT` v2.0.0 being installed
- Update Facebook Graph API to 8.0
- Update Amazon fetch-profile URL
- Fix Azure AD Tenant, unable to load certificate
- Fix Okta well-known URL
- Updated Discord's API hostname from discordapp.com to discord.com
- Pass `client_secret` in auth-complete on Kakao backend

## [3.4.0](https://github.com/python-social-auth/social-core/releases/tag/3.4.0) - 2020-06-21

### Added
- Zoom backend

### Changed
- Directly use `access_token` in Azure Tenant backend
- Support Apple JWT audience 
- Update partial session cleanup to remove old token from session too
- Fetch user email in Okta integration
- Improve Python 3.9 compatibility
- Send proxies in request
- Improve error handling in Apple backend

## [3.3.3](https://github.com/python-social-auth/social-core/releases/tag/3.3.3) - 2020-04-16

### Changed
- Updated list of default user protected fields to include admin flags and password

## [3.3.2](https://github.com/python-social-auth/social-core/releases/tag/3.3.2) - 2020-03-25

### Changed
- Updated package upload method to use `twine`

## [3.3.1](https://github.com/python-social-auth/social-core/releases/tag/3.3.1) - 2020-03-25

### Changed
- Reverted [PR #388](https://github.com/python-social-auth/social-core/pull/388/) due to
  dependency license incompatibility

## [3.3.0](https://github.com/python-social-auth/social-core/releases/tag/3.3.0) - 2020-03-17

### Added
- Okta backend
- Support for SAML Single Logout
- SimpleLogin backend
- SurveyMonkey backend
- HubSpot backend
- MRG backend
- Sign in with Apple backend
- Allow ignoring of default protected user fields with option `SOCIAL_AUTH_NO_DEFAULT_PROTECTED_USER_FIELDS`
- Support for users field names mapping
- Added GithubAppAuth backend

### Changed
- Add refresh token to Strava backend, change username and remove email
- Update test runner to PyTest
- Add python 3.7 CI target
- Send User-Agent header on Untappd backend
- Updated Naver API support from XML to JSON format
- Use `unidecode` to cleanup usernames from unicode characters
- Update Twitch API support from v3 to v5
- Properly setup `pytest` version for Python2 and Python3
- Fix some spelling mistakes in docstrings
- Fix old fields from FIELDS_STORED_IN_SESSION persisting in session
- Github: pass access token in a header instead of in a query parameter.
- Update Kakao API support from v1 to v2
- Update Twitch API support to v5
- Updated Patreon API support from v1 to v2 per issue #307
- Fix `user_details` in user pipeline to allow model attributes to be updated
- Updated Atlassian API urls

## [3.2.0](https://github.com/python-social-auth/social-core/releases/tag/3.2.0) - 2019-05-30

### Added
- Cognito backend
- OpenStack (openstackid and openstackid-dev) backends

### Changed
- Updated Linkedin backend to v2 API
- Facebook: Update to use the latest Graph API v3.2
- Send User-Agent header on GitHub backend
- Remove profile scope and verification at hash on Elixir backend
- Mark description as Markdown for PyPI
- Use `hmac.compare_digest` for constant time comparision
- Replace deprecated Google+ API usage in GoogleOpenIdConnect
- Defined scope separator for Strava backend
- Ensure `saml_config.json` is included by addint it to `MANIFEST.in`
- Include `email_verified` as part of user details on Auth0 backend
- Include Shopify `version` parameter on Shopify session setup
- Define `SOCIAL_AUTH_SHOPIFY_API_VERSION` setting to override default API version
- Check user `id` attribute existence before using it
- Pull `last_name` from `family_name` in Cognito backend
- Ignore key errors on Naver backend for missing attributes

## [3.1.0](https://github.com/python-social-auth/social-core/releases/tag/3.1.0) - 2019-02-20

### Added
- Universe Ticketing backend
- Auth0.com authentication backend

### Changed
- Update Bungie backend dropping any Django reference
- Enable and fix JWT related tests
- Remove PyPy support from Tox
- Drop support for Python 3.4 in Tox
- Allow to override JWT decode options in Open ID Connect base backend
- Pass access token via Authorization header to Google user data url
- Updated `user_data` method in `AzureADOAuth2` to return `access_token` if
  `id_token` is not present in response

## [3.0.0](https://github.com/python-social-auth/social-core/releases/tag/3.0.0) - 2019-01-14

### Changed
- Updated Azure B2C to extract first email from list if it's a list
- Replace deprecated Google+ API usage with https://www.googleapis.com/oauth2/v3/userinfo
- Updated Azure Tenant to fix Nonetype error
- Updated comment denoting incorrect setting name
- Yandex: do not fail when no email is present
- Mediawiki: do not fail when no email is present
- Mediawiki: enhance `get_user_details` to return more details

## [2.0.0](https://github.com/python-social-auth/social-core/releases/tag/2.0.0) - 2018-10-28

### Added
- Telegram authentication backend
- Keycloak backend is added with preliminary OAuth2 support
- Globus OpenId Connect backend
- Discord OAuth2 backend
- SciStarter OAuth2 backend
- Flat OAuth2 backend
- ELIXIR OpenId Connect backend
- Atlassian OAuth2 backend

### Changed
- GitHub backend now uses `state` parameter instead of `redirect_state`
- Correct setting name on AzureAD Tenant backend
- Introduce access token expired threshold of 5 seconds by default
- Delete partial token from session if still present
- Use `userPrincipalName` to set `username` and `email` accordingly
- Send authorization headers to Kakao OAuth2, properly fill user details
- LINE API update to v2.1
- Use `unitest2` with Python 3
- Update Slack backend to use computed usename on teams setups
- Enforce `unicode_literals` on Slack backend
- Update ORCID backend to support Member API
- Updated Pixelpin backend to use the new OpenId Connect service
- Update `sanitize_redirect` to invalidate redirects like `///evil.com`
- Update Coinbase API endpoint
- Dropped Python 3.3 support
- Updated Weixin backend to use `urlencode` from `six`
- Updated Google+ backend to properly process requests with `id_token`
- Updated OpenId connect dependencies

## [1.7.0](https://github.com/python-social-auth/social-core/releases/tag/1.7.0) - 2018-02-20

### Changed
- Update EvenOnline token expiration key
- Update OpenStreetMap URL to `https`
- Fix LinkedIn backend to send the oauth_token as `Authorization` header
- Fixed `extra_data` update to use the `alias` as key too
- Make `signed_request` optional in Facebook App OAuth2 backend
- Support string and lists on SAML permanent id value
- Correct sending `params` sending on `GET` access-token retrieval case
- Ensure b2c policy name check
- Use `extras_requrie` to specify python specific version dependencies

### Added
- Added support for AzureAD B2C OAuth2
- Added LinkedIn Mobile OAuth2 backend

## [1.6.0](https://github.com/python-social-auth/social-core/releases/tag/1.6.0) - 2017-12-22

### Changed
- Fix coinbase backend to use api v2
- Default `REDIRECT_STATE` to `False` in `FacebookOAuth2` backend.
- Add revoke token url for Coinbase OAuth2 backend
- Fix LinkedIn backend to send `oauth_token` as request header
- Make partial step decorator handle arguments

### Added
- Added support for ChatWork OAuth2 backend

## [1.5.0](https://github.com/python-social-auth/social-core/releases/tag/1.5.0) - 2017-10-28

### Changed
- Fix using the entire SAML2 nameid string
- Prevent timing attacks against state token
- Updated GitLab API version to v4
- Enforce UTC when calculating access token expiration time
- Cleanup user attributes update from social details
- Send authorization header on Reddit auth

### Added
- Added support for tenant for Azure AD backend
- Added JWT validation for Azure AD backend
- Added support for Bungie.net OAuth2 backend
- Added support for Eventbrite OAuth2 backend
- Added support for OpenShift OAuth2 backend
- Added support for Microsoft Graph OAuth2 backend

## [1.4.0](https://github.com/python-social-auth/social-core/releases/tag/1.4.0) - 2017-06-09

### Changed
- Fix path in import BaseOAuth2 for Monzo
- Fix auth header formatting problem for Fitbit OAuth2
- Raise AuthForbidden when provider returns 401.
- Update Facebook API to version 2.9
- Speed up authorization process for VKAppOAuth2
- Apply same sanitization as on connect to disconnect.
- Disable `redirect_state` usage on Disqus backend

### Added
- Added Udata OAuth2 backend
- Added ORCID backend
- Added feature to get all extra data from backend through `GET_ALL_EXTRA_DATA` boolean flag.
- Added Patreon provider

## [1.3.0](https://github.com/python-social-auth/social-core/releases/tag/1.3.0) - 2017-05-06

### Added
- Use extra_data method when refreshing an `access_token`, ensure that
  auth-time is updated then
- Added 500px OAuth1 backend
- Added Monzo OAuth2 backend
- Added `get_access_token` method that will refresh if expired

### Changed
- Updated email validation to pass the partial pipeline token if given.
- Prefer passed parameters in `authenticate` method
- Properly discard already used verification codes
- Save SAML attributes in `extra_data`
- Note `id_token` in GooglePlusAuth's AuthMissingParameter

## [1.2.0](https://github.com/python-social-auth/social-core/releases/tag/1.2.0) - 2017-02-10

### Added
- Limit Slack by team through `SOCIAL_AUTH_SLACK_TEAM` setting

### Changed
- Enable defining extra arguments for AzureAD backend.
- Updated key `expires` to `expires_in` for Facebook OAuth2 backend
- Updated Slack `id` fetch to default to user `id` if not present in response

## [1.1.0](https://github.com/python-social-auth/social-core/releases/tag/1.1.0) - 2017-01-31

### Added
- Mediawiki backend
- Strategy method to let implementation cleanup arguments passed to
  the authenticate method

### Changed
- Removed OneLogin SAML IDP dummy settings while generating metadata xml
- Fixed Asana user details response handling
- Enforce defusedxml version with support for Python 3.6
- Updated documentation URL in backends

## [1.0.1](https://github.com/python-social-auth/social-core/releases/tag/1.0.1) - 2017-01-23

### Changed
- Fixed broken dependencies while building the package

## [1.0.0](https://github.com/python-social-auth/social-core/releases/tag/1.0.0) - 2017-01-22

### Added
- Store partial pipeline data in an storage class
- Store `auth_time` with the last time authentication toke place, use
  `auth_time` to determine if access token expired
- Ensure that `testkey.pem` is distributed
- Added Asana OAuth2 backend

### Changed
- Removed the old `save_status_to_session` to partialize a pipeline run

## [0.2.1](https://github.com/python-social-auth/social-core/releases/tag/0.2.1) - 2016-12-31

### Added
- Defined `extras` for SAML, and "all" that will install SAML and OpenIdConnect
- Added `auth_time` in extra data by default to store the time that the authentication toke place

### Changed
- Remove set/get current strategy methods
- Fixed the `extras` requirements defined in the setup.py script

## [0.2.0](https://github.com/python-social-auth/social-core/releases/tag/0.2.0) - 2016-12-31

### Changed
- Reorganize requirements, make OpenIdConnect optional
- Split OpenIdConnect from OpenId module, install with `social-core[openidconnect]`

## [0.1.0](https://github.com/python-social-auth/social-core/releases/tag/0.1.0) - 2016-12-28

### Added
- Added support for GitLab OAuth2 backend.
  Refs [#2](https://github.com/python-social-auth/social-core/issues/2)
- Added support for Facebook OAuth2 return_scopes parameter.
  Refs [#818](https://github.com/omab/python-social-auth/issues/818)
- Added support for per-backend USER_FIELDS setting. Refs [#661](https://github.com/omab/python-social-auth/issues/661)
- Added `expires_in` as `expires` for LinkedIn OAuth2. Refs [#666](https://github.com/omab/python-social-auth/issues/666)
- Added `SOCIAL_AUTH_USER_AGENT` setting to override the default User-Agent header.
  Refs [#752](https://github.com/omab/python-social-auth/issues/752)
- Enabled Python 3 SAML support through python3-saml package.
  Refs [#846](https://github.com/omab/python-social-auth/issues/846)
- Added better username characters clenup rules, support for a configurable
  cleanup function through SOCIAL_AUTH_CLEAN_USERNAME_FUNCTION (import path)
  setting.
- Added configurable option SOCIAL_AUTH_FACEBOOK_*_API_VERSION to
  override the default Facebook API version used.
- Add Lyft OAuth2 implementation to Python Social Auth (port from [#1036](https://github.com/omab/python-social-auth/pull/1036/files)
  by iampark)
- Added the ability to specify a pipeline on a per backend basis (port from [#1019](https://github.com/omab/python-social-auth/pull/1019)
  by keattang)
- Add support for MailChimp as an OAuth v2 backend (port from [#1037](https://github.com/omab/python-social-auth/pull/1037)
  by svvitale)
- Added Shimmering backend (port from [#1054](https://github.com/omab/python-social-auth/pull/1054)
  by iamkhush)
- Added Quizlet backend (port from [#1012](https://github.com/omab/python-social-auth/pull/1012)
  by s-alexey)
- Added Dockerfile to simplify the running of tests (`make docker-tox`)

### Changed
- Changed Facebook refresh token processing. Refs [#866](https://github.com/omab/python-social-auth/issues/866)
- Update Google+ Auth tokeninfo API version, drop support for deprecated API scopes.
  Refs [#791](https://github.com/omab/python-social-auth/issues/791).
- Fixed OAuth1/2 early state validation on error responses.
- Disabled SAML test when running on Travis-ci on Python 3.5 since it [segfaults](https://travis-ci.org/python-social-auth/social-core/jobs/186790227)
  probably by a bad build in one of the dependencies
- Fixed Xing backend testing broken by previous change
- Fixed Xing backend dropping `callback_uri` and `oauth_verifier` parameters on authenticated API calls.
  Refs [#871](https://github.com/omab/python-social-auth/issues/871)
- Updated slack backend implementation, update API endpoints used, add test case.
- Changed Dailymotion user data API endpoint
- Changed how "false" values are treated in the user attributes update pipeline
- Fix google OpenID Connect (port from [#747](https://github.com/omab/python-social-auth/pull/747)
  by mvschaik)
- Update Facebook api version to v2.8 (port from [#1047](https://github.com/omab/python-social-auth/pull/1047)
  by browniebroke)
- Remove Facebook2OAuth2 and Facebook2AppOAuth2 backends (port from [#1046](https://github.com/omab/python-social-auth/pull/1046)
  by browniebroke)
- change username, email and fullname keys (port from [#1028](https://github.com/omab/python-social-auth/pull/1028)
  by inlanger)
- Moves fix convert username to string (port from [#1021](https://github.com/omab/python-social-auth/pull/1021)
  by WarmongeR1)
- Fix auth_params for Stripe backend (port from [#1034](https://github.com/omab/python-social-auth/pull/1034)
  by dchanm)
- Preserve order of backends in BACKENDSCACHE (port from [#1004](https://github.com/omab/python-social-auth/pull/1004)
  by tsouvarev)
- Don't lose custom exception message on raising AuthCanceled (port from [#1062](https://github.com/omab/python-social-auth/pull/1062)
  by dotsbb)
- Fixed VK backend (port from [#1007](https://github.com/omab/python-social-auth/pull/1007)
  by DeKaN)
- Updated Dropbox backend (port from [#1018](https://github.com/omab/python-social-auth/pull/1018)
  by illing2005)

## [0.0.1](https://github.com/python-social-auth/social-core/releases/tag/0.0.1) - 2016-11-27

### Changed
- Split from the monolitic [python-social-auth](https://github.com/omab/python-social-auth)
  codebase
