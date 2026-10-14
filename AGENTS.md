# Agent guidance for social-auth-core

This file captures agent-specific guidance for working in the social-auth-core
codebase. User-facing integration and configuration guidance belongs in the
[social-docs](https://github.com/python-social-auth/social-docs) repository
rather than being duplicated here. The companion Django integration lives in
[social-auth-app-django](https://github.com/python-social-auth/social-app-django).

## Project overview

- social-auth-core is the framework-agnostic core of Python Social Auth. It
  implements authentication protocols, provider backends, pipelines, and the
  strategy and storage interfaces used by framework integrations.
- The library runs inside an embedding application. Framework sessions,
  persistence, HTTP routes and responses, and local login behavior are supplied
  through strategy and storage implementations.
- [social-auth-app-django](https://github.com/python-social-auth/social-app-django)
  is the companion Django integration. It owns the Django strategy and storage
  implementations, models and migrations, views, URLs, middleware, templates,
  and other Django-specific behavior.

## Code expectations

- Follow existing backend, pipeline, strategy, storage, exception, and test
  patterns. Put behavior shared by a protocol family in its base class rather
  than copying it across provider backends.
- Keep the core framework-agnostic. Django-specific behavior belongs in
  [social-auth-app-django](https://github.com/python-social-auth/social-app-django);
  other framework-specific behavior belongs in the corresponding integration
  repository. Expose it through the existing strategy or storage interfaces.
- When changing a public interface consumed by
  [social-auth-app-django](https://github.com/python-social-auth/social-app-django),
  review the companion implementation and coordinate any required compatibility,
  test, changelog, and documentation changes across both repositories.
- Prefer the repository's configured Ruff formatting and linting rules. Use
  human-readable Ruff rule names in overrides rather than cryptic rule codes.
- Add type hints to new and changed interfaces. Use
  `from __future__ import annotations` and `TYPE_CHECKING` imports where they
  avoid runtime import cycles. Keep the distributed `py.typed` contract in
  mind when changing public types.
- Preserve backward compatibility unless the change is intentionally breaking.
  Provider names, setting names, storage method signatures, pipeline argument
  names, and persisted data formats are public integration contracts.
- Resolve settings through the strategy and backend setting helpers so global
  and per-backend configuration precedence remains consistent.
- Use the structured social-auth exception hierarchy and set the correct
  operation stage. Do not leak provider responses, tokens, secrets, or personal
  data through exception text or routine logging.
- Route provider HTTP traffic through the shared request helpers so TLS
  verification, proxies, timeouts, user agents, HTTP error mapping, and tests
  remain consistent.
- For security-sensitive comparisons, randomness, token validation, XML
  parsing, and redirects, reuse the project's established helpers and hardened
  dependencies instead of introducing local alternatives.
- Add focused regression tests for behavior changes. Shared protocol changes
  need base-class coverage and representative provider coverage; provider-only
  changes belong in that provider's test module.
- Keep development dependencies exactly pinned. Follow the existing compatible
  lower-bound and upper-bound style for runtime dependencies, documenting any
  unusual constraint next to the declaration.
- Write commit messages using Conventional Commits in the form
  `<type>(<optional scope>): <description>`, using types such as `feat`, `fix`,
  `docs`, `test`, `refactor`, `ci`, and `chore`.

## Documentation and changelog expectations

- The user-facing documentation source is in the
  [social-docs repository](https://github.com/python-social-auth/social-docs/tree/master/docs)
  and is published at <https://python-social-auth.readthedocs.io/en/latest/>.
  Update the relevant backend, configuration, pipeline, strategy, storage, or
  exception page when changing a public interface or required integration
  behavior. This documentation covers both social-auth-core and framework
  integrations such as social-auth-app-django.
- Match the surrounding reStructuredText style in social-docs. Prefer semantic
  Sphinx cross-references inside that repository and use the published
  `/en/latest/` URLs when linking to documentation from this repository.
- Document new backends and all user-configurable settings. Explain security
  requirements and migration steps where an otherwise valid configuration can
  change identity binding or flow validation.
- Add user-visible changes to the `Unreleased` section of `CHANGELOG.md`, using
  `Security`, `Added`, `Changed`, `Fixed`, or `Removed` as appropriate. Do not
  alter entries for released versions.
- Keep changelog entries concise. Put operational detail in social-docs and link
  to it when useful.

## Authentication and security guardrails

- Treat browser callback data and provider responses as untrusted until the
  applicable protocol checks have completed. Preserve state, nonce, request-ID,
  signature, issuer, audience, subject, destination, and user-binding checks
  where the backend requires them.
- Use stable, provider-scoped account identifiers. Do not silently replace them
  with email addresses, usernames, display names, or other mutable claims.
  Changes to identifier keys or migration behavior require conflict and legacy
  data tests.
- Keep authentication, association, disconnection, and partial-resume flows
  bound to the initiating session and authenticated local user. Custom or
  association-only flows must not bypass those bindings.
- Preserve redirect sanitization, TLS verification, protected local user fields,
  and evidence-based identifier migration as the supported defaults. Make any
  deliberate security-weakening option explicit in code, tests, documentation,
  and the threat model when applicable.
- Treat custom pipelines and strategy or storage implementations as security
  boundaries. Keep pipeline data provenance clear, especially across saved
  partials, and do not reintroduce unvalidated request data as trusted identity
  claims.
- Mock provider traffic in tests. Tests must not depend on live identity
  providers, external discovery documents, or mutable remote account data.
- Review `THREAT_MODEL.md` when changing public authentication entry points,
  supported protocols or backends, strategy or storage interfaces, pipeline and
  partial-resume behavior, outbound network or filesystem access, or
  security-relevant defaults for TLS, redirects, state, nonces, PKCE, assertion
  validation, account identifiers and migration, email-code expiry, or protected
  user fields.
- Review does not necessarily require an edit. Update the threat model in the
  same change only when its scope, actors, trust boundaries, assumptions,
  claimed or disclaimed security properties, downstream responsibilities, known
  misuse or non-findings, or triage dispositions change or leave a gap,
  following its "Conditions that change this model" section. Features covered
  by existing guidance do not need individual entries. Keep feature-level API,
  configuration, implementation, and limit details in the relevant project
  documentation; link to them only when needed to explain a distinct boundary,
  exception, or triage outcome.

## Testing and linting instructions

- Install a complete development environment with `uv sync --all-extras --dev`.
  SAML development may also require the system xmlsec and libxml2 development
  packages used by CI.
- Run the test suite with `uv run pytest`. During development, run the narrowest
  relevant test module first, then expand coverage in proportion to the change.
- Use `uvx tox` when compatibility across all supported Python versions matters;
  select a specific environment such as `uvx tox -e py310` for focused checks.
- Run repository formatting and linting with `uvx prek run --all-files`. Let the
  configured hooks invoke Ruff, rumdl, codespell, actionlint, and zizmor rather
  than substituting ad-hoc command lines.
- Run `uv run --all-extras pyright`,
  `uv run --all-extras mypy social_core`, and
  `uv run --all-extras ty check` for typing changes.
- Run Pylint with the CI-equivalent environment and command:
  `uv run --no-sync pylint social_core/`.
- Tests that exercise optional dependencies should use the matching project
  extras and existing fixtures. Keep network calls mocked with `responses` or
  the existing test helpers, and assert both successful identity binding and
  rejection at relevant failure boundaries.
- For changes to contracts used by
  [social-auth-app-django](https://github.com/python-social-auth/social-app-django),
  run or update the relevant companion tests as well, following that
  repository's `AGENTS.md`.
