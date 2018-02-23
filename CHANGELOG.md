# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased](https://github.com/python-social-auth/social-core/commits/master)

### Changed
- GitHub backend now uses `state` parameter instead of `redirect_state`
- Correct setting name on AzureAD Tenant backend
- Introduce access token expired threshold of 5 seconds by default
- Delete partial token from session if still present
- Use `userPrincipalName` to set `username` and `email` accordingly
- Send authorization headers to Kakao OAuth2, properly fill user details
- Add settings for controlling email validation code expiry

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
