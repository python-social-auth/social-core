# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased](https://github.com/python-social-auth/social-core/commits/master)

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

### Chaged
- Split from the monolitic [python-social-auth](https://github.com/omab/python-social-auth)
  codebase
