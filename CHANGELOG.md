# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased](https://github.com/python-social-auth/social-core/commits/master)

### Added
- Add support for MailChimp as an OAuth v2 backend (port from [#1037](https://github.com/omab/python-social-auth/pull/1037)
  by svvitale)
- Added Shimmering backend (port from [#1054](https://github.com/omab/python-social-auth/pull/1054)
  by iamkhush)
- Added Quizlet backend (port from [#1012](https://github.com/omab/python-social-auth/pull/1012)
  by s-alexey)
- Added Dockerfile to simplify the running of tests (`make docker-tox`)

### Changed
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
