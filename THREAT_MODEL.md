# Threat model

## 1. Document status

| Field | Value |
| --- | --- |
| Project | social-auth-core |
| Project version | 6.1.1 development tree |
| Commit | `394aa874b4a39fae6bbfa78380b1cdccbd009488` |
| Model date | 2026-10-14 |
| Authors | Python Social Auth maintainers |
| Status | Accepted on 2026-10-14 |

This model is versioned with social-auth-core. Reports against a released
version are evaluated against the model shipped with that version, rather than
the model at the tip of the default branch. (maintainer)

The project does not maintain release-specific README links. The README points
to the current model for discovery; the model for an older release remains in
that release's source distribution and repository tag. (maintainer)

Report violations of the properties in section 8 privately through the
[project security policy](https://github.com/python-social-auth/social-core/security/policy).
Reports covered by sections 3 or 9 may be closed by citing this model.
(maintainer)

Provenance tags used below are `(documented)` for statements supported by the
project documentation and `(maintainer)` for decisions accepted as part of this
model. Confidence at acceptance: **29 documented / 60 maintainer / 0 inferred**.

social-auth-core is an in-process Python library that implements common social
authentication and authorization flows. It connects an embedding web
application to external identity providers, validates protocol responses, and
runs application-integrated pipelines that locate, create, associate, update,
or disconnect local users. It does not itself run an HTTP server or provide a
complete web framework integration. (documented)

## 2. Scope and intended use

The intended caller is a trusted Python web application using a supported
framework integration, strategy, and storage implementation. The library is
designed to execute inside that application while processing authentication,
account-association, and disconnection requests. See the
[strategy](https://python-social-auth.readthedocs.io/en/latest/strategies.html),
[storage](https://python-social-auth.readthedocs.io/en/latest/storage.html), and
[pipeline](https://python-social-auth.readthedocs.io/en/latest/pipeline.html)
contracts. (documented)

| Component family | Representative entry points | External effects | Status |
| --- | --- | --- | --- |
| Flow orchestration | `do_auth`, `do_complete`, `do_disconnect` | Reads request and session state; returns framework responses | In scope |
| Authentication pipelines | Default authentication, association, partial, email-validation, and disconnection pipelines | Reads and writes application storage; can send validation email through the strategy | In scope |
| Protocol implementations | OAuth 1/2, OpenID Connect, OpenID, SAML, CAS, and signed callbacks | Redirects browsers and communicates with configured providers | In scope |
| Provider backends | Bundled classes under `social_core.backends` | Exchanges credentials and retrieves provider data | In scope |
| Strategy and storage abstractions | `BaseStrategy`, `BaseStorage`, and their mixins | Delegates sessions, persistence, templates, login, and email to the embedding application | In scope at the interface boundary; implementations are trusted |
| Optional runtime integrations | SAML, Google One Tap, Shopify, and other packaged extras | Protocol-specific parsing, validation, or provider API access | In scope when installed |
| Tests, CI, packaging scripts, generated files, and static artwork | Repository support files | Build, test, or presentation only | Out of scope |

All shipped runtime Python code is covered. A finding in a provider-specific
backend is evaluated under the same identity-flow properties as the shared
protocol base, subject to that provider's documented protocol and capabilities.
(maintainer)

## 3. Out of scope

The following are explicit non-goals:

- Operating social-auth-core as a standalone network service. It is an
  in-process library and relies on a framework integration for routes, request
  parsing, responses, sessions, and login. (documented)
- Defending against an attacker who controls the application process,
  configuration, strategy, storage implementation, custom backend, or custom
  pipeline code. Those components execute with the application's authority.
  (maintainer)
- Detecting a configured identity provider that impersonates users or supplies
  false claims within its own backend namespace. A provider is the identity
  authority for that namespace. (maintainer)
- Providing application authorization, account-recovery policy, MFA policy,
  session-cookie security, route-level CSRF protection, TLS termination, Host
  validation, or trusted-proxy configuration. (documented)
- Guaranteeing provider availability or placing quantitative bounds on hostile
  input size, request rate, CPU use, memory use, or provider response time.
  (maintainer)
- Encrypting provider credentials or tokens at rest. Persistence and access
  control are supplied by the embedding application's storage integration.
  (maintainer)
- Supply-chain, release-signing, CI, dependency freshness, and repository
  administration controls. (maintainer)
- Tests, CI configuration, packaging utilities, generated files, and static
  artwork shipped in the repository. (maintainer)

## 4. Trust boundaries and data flow

The public integration interfaces are the main trust boundary. Application
configuration and conforming strategy, session, storage, backend, and pipeline
extensions are trusted. Browser-controlled request data and remote provider
responses are untrusted until the applicable backend validates and normalizes
them. (maintainer)

The normal trust transitions for redirect-based backends are:

1. An untrusted browser request enters a trusted framework route and strategy.
2. social-auth-core creates correlation state and redirects the browser to a
   configured provider.
3. Untrusted callback parameters return through the framework integration.
4. Where the protocol defines correlation, the backend correlates the callback
   with session or persisted state, exchanges credentials over TLS, and
   validates provider responses according to the protocol and backend.
5. Validated identity data enters the configured pipeline. The pipeline binds
   the provider namespace and stable provider identifier to a local user through
   trusted storage.
6. The trusted framework integration establishes the local login session and
   performs a validated redirect.

Signed-callback and direct signed-token backends can differ. Telegram validates
the bot-token HMAC and a 24-hour callback age directly. Facebook Limited Login
validates a client-supplied signed ID token's provider signature and applicable
identity and time claims, but intentionally does not enforce its nonce. The
Odnoklassniki iframe app validates the launch signature and provider user, but
has no application-controlled initiation value; in an authenticated local
session, core therefore accepts only an OK identity already associated with
that user. These flows do not bind their signed input to an initiating browser
session or make it single-use. (documented)

OpenID backends bind positive assertions to backend-scoped discovery state in
the initiating browser session or a session selected by the provider-signed
return URL. The generic OpenID backend intentionally accepts a provider selected
by the application user. Fixed-provider backends additionally require the exact
HTTPS provider endpoint discovered during initiation. (documented)

Partial pipelines add a persistence boundary. Authentication and disconnection
partials must retain their flow type and initiating user/session context;
externally resumed partials require the documented confirmation path before
request data is consumed. (documented)

Reachability determines whether a finding is in scope:

- Flow and pipeline findings must be reachable from a public authentication,
  association, disconnection, refresh, or partial-resume operation.
- Backend parser findings must be reachable from browser-controlled callback
  data or a provider response processed by that backend.
- HTTP client findings must be reachable from a bundled backend using a
  configured endpoint, or from an input that a bundled protocol intentionally
  permits an untrusted caller to select.
- Strategy and storage findings must concern the core interface contract;
  defects solely inside an application's implementation are outside the model.
  (maintainer)

## 5. Assumptions about the environment

- A supported Python runtime and the documented dependencies provide their
  normal memory safety, cryptography, TLS, URL parsing, and XML/JWT validation
  behavior. (maintainer)
- The embedding framework supplies authenticated-user state, session isolation,
  session rotation where appropriate, CSRF protection for application routes,
  and correct request/response primitives. (maintainer)
- For ordinary authenticated account linking, the framework integration
  preserves the same authenticated local user from initiation through callback,
  or rejects and restarts the flow if that principal changes. Core-enforced
  association-only flows additionally persist and verify the initiating user.
  (maintainer)
- Storage enforces the uniqueness and atomicity needed for provider identity
  associations and does not permit untrusted users to alter session, nonce,
  association, code, or partial-pipeline records. (maintainer)
- System time is sufficiently accurate for token, nonce, assertion, and email
  validation-code expiry checks. (maintainer)
- Provider endpoints, client credentials, signing keys, certificates, proxy
  settings, and application redirect allowlists are supplied by a trusted
  operator. (maintainer)
- The deployment validates the HTTP `Host` header and accepts forwarded headers
  only from trusted proxies, because absolute callback and redirect URLs may be
  derived from the request host. See
  [Security considerations](https://python-social-auth.readthedocs.io/en/latest/security.html).
  (documented)
- The library opens outbound HTTP connections to providers and may log through
  the `social` logger. The opt-in debug pipeline writes authentication data to
  standard output. The Azure AD workload-identity path can read a configured
  token file or its documented environment-variable location. The core does not
  listen on sockets, spawn child processes, or install signal handlers.
  (maintainer)
- Separate backend instances or request contexts are used as intended by the
  framework integration; application extensions are responsible for their own
  shared mutable state and concurrency behavior. (maintainer)

### 5a. Build-time and configuration variants

social-auth-core has no compile-time security modes. Runtime settings and the
selected backend, pipeline, strategy, and storage implementation define a
family of deployments. (maintainer)

| Configuration family | Supported posture | Effect on the model |
| --- | --- | --- |
| Transport and destinations | Provider endpoints use HTTPS; `VERIFY_SSL` remains enabled; endpoint and proxy settings are trusted; finite request timeouts are retained | Cleartext HTTP, disabled certificate verification, or untrusted endpoint/proxy configuration removes transport and destination guarantees |
| Redirects | `SANITIZE_REDIRECTS` remains enabled; HTTP(S) destinations use an approved host and scheme; private-use destinations use an explicitly approved scheme | Disabling sanitization or broadly trusting hosts/schemes removes the safe-redirect property; private-use schemes do not receive host validation |
| OAuth/OIDC | Backend-required state and nonce validation remains enabled; `JWT_ALGORITHMS`, `JWT_DECODE_OPTIONS`, issuer, audience, JWKS, leeway, and PKCE settings match the provider and protocol | Settings that disable required validation or enable unsuitable algorithms are outside the corresponding authentication guarantee |
| SAML | Trusted IdP certificates and endpoints are configured; `SECURITY_CONFIG` retains the validations required by the deployment | Disabling signature, assertion, request-correlation, or destination checks removes the affected SAML guarantee |
| Account identifiers | Bundled backends use stable `ID_KEY` values where providers expose them; Drip, Last.fm, and Mixcloud are association-only; EmailAuth and UsernameAuth rely on application credential and validation policy; migrations require evidence except for audited built-in compatibility transitions | Audited defaults accept a documented missing-evidence race; mutable custom identifiers, using an exception outside its conditions, or explicitly enabling unverified migration elsewhere accepts additional account-binding risk |
| Telegram callback | The callback has a valid bot-token HMAC and an `auth_date` no more than 24 hours old | Authenticity and age are checked, but initiation, browser-session correlation, and single-use replay protection are not provided |
| Facebook Limited Login | The client-supplied ID token passes the backend's provider-signature, identity, and time-claim validation | Nonce, initiation, browser-session correlation, and single-use replay protection are not provided |
| Odnoklassniki iframe app | The launch signature and provider user match; an authenticated local session accepts only an OK identity already associated with that user | Initiation, browser-session correlation, and single-use replay protection are not provided; new account association from an authenticated session is rejected |
| Pipelines and fields | The default security-relevant pipeline ordering is preserved; custom pipelines preserve equivalent validation and association ordering; protected account fields remain protected | Removing or reordering validation, trusting unverified email, or unprotecting authorization-sensitive fields transfers responsibility to the integrator |
| Partial and email flows | Partial storage preserves ownership/type metadata; external resume confirmation is implemented; email codes retain a finite expiry | Custom resume behavior or disabled expiry removes the corresponding replay and flow-binding guarantees |
| Application policy | Inactive-user, allowlist, group, and token-revocation settings match application policy | These settings define policy; they do not by themselves prove identity or make untrusted claims trustworthy |

An issue that requires an explicit security-weakening configuration is
`OUT-OF-MODEL: non-default-build`. Backend-specific defaults that legitimately
vary by protocol, such as whether PKCE is required for a confidential client,
remain supported unless the backend documentation requires a stronger posture.
Audited entries in `UNVERIFIED_LEGACY_TRANSITIONS` are supported compatibility
defaults, not non-default builds; they accept the documented first-login race
when stored evidence is missing. Explicitly enabling unverified migration for
other transitions is a security-weakening configuration. (maintainer)

## 6. Assumptions about inputs

| Entry point or operation | Input | Attacker-controlled? | Caller responsibility |
| --- | --- | --- | --- |
| `do_auth` | Request fields such as `next` and configured fields stored in the session | Yes | Route-level CSRF policy, request limits, and a validated Host value |
| `do_complete` / backend `auth_complete` | OAuth codes, state, signed payloads, SAML assertions, OpenID responses, errors, and provider-specific callback fields | Yes | Preserve correlation state where the backend uses it and, for ordinary account linking, the initiating authenticated user; add an application binding for Telegram or the Odnoklassniki iframe app when initiation or single-use is required |
| Facebook Limited Login `do_auth` | Client-supplied signed ID token | Yes, until validated | Add application-level initiation and single-use binding when login-CSRF or account-linking replay protection is required |
| Provider token/user-info/discovery calls | HTTP status, headers, JSON, JWT, XML, and form responses | Yes, until validated | Configure the intended HTTPS provider endpoints and trusted TLS roots; restrict egress where required |
| Generic OpenID initiation | Claimed identifier/provider URL | Yes when exposed by the application | Decide whether user-selected discovery is appropriate and apply deployment egress policy |
| `do_disconnect` | Authenticated user, association selector, and redirect | Redirect and selector may be attacker-controlled; user context must be trusted | Authenticate and authorize the route and preserve the user-bound session |
| Partial-pipeline resume | Partial token, verification data, saved request data, and current user/session | Links and request data may be attacker-controlled | Implement external-resume confirmation and protect partial storage |
| Refresh and revocation | Stored token material and provider responses | Stored material is trusted; provider response is not | Protect token storage and authorize the operation |
| Settings and backend metadata | Secrets, endpoints, algorithms, certificates, scopes, mappings, and policy | No | Restrict configuration to trusted operators |
| Storage record identity and metadata | User and model objects, timestamps, ownership, and integrity metadata produced by conforming storage | No | Enforce integrity, uniqueness, expiry persistence, and tenant isolation |
| Values persisted in sessions, associations, codes, and partials | Saved request fields, redirects, callback data, provider claims, and pipeline values | Retains the original source's provenance | Preserve provenance across persistence and revalidate attacker-controlled values when consumed |
| Custom pipeline/backend arguments | Extension-defined data | Defined by the integrator | Document and enforce any additional trust boundary |

Callback and provider inputs may be malformed and may contain missing, repeated,
unexpected, or extremely large values. The library makes no quantitative input
size or rate guarantee; the embedding stack must impose appropriate limits.
Persistence protects record integrity but does not turn request- or
provider-derived fields into trusted input. (maintainer)

## 7. Adversary model

In-scope adversaries are unauthenticated remote clients controlling a browser or
crafting callback requests, authenticated users attempting to link or disconnect
accounts they do not own, and remote provider responses that are malformed,
replayed, inconsistent, or malicious prior to successful protocol validation.
(maintainer)

These adversaries may initiate concurrent flows, replay observed links or
parameters, choose any public request value, interrupt flows, and operate their
own accounts at configured providers. They may attempt login CSRF, account
confusion, association theft, unsafe redirects, token disclosure, or validation
bypass. They do not control the application process, trusted configuration,
session/storage contents, provider signing credentials, TLS trust store, or
conforming extensions. (maintainer)

A configured provider is trusted to assert identities and claims within its own
backend namespace after protocol validation. Compromise of that authority is
outside the model, but a provider response must not acquire authority in another
backend namespace or bypass the local flow and user bindings. (maintainer)

## 8. Security properties provided

| Property and conditions | Violation symptom | Severity | Provenance |
| --- | --- | --- | --- |
| A backend that implements callback correlation accepts a callback only for the initiating flow and session after its state, nonce, or request-ID check succeeds; Telegram instead accepts only callbacks with a valid bot-token HMAC and an age of at most 24 hours, while Facebook Limited Login accepts only ID tokens passing its provider-signature, identity, and time-claim validation; neither exception claims initiation, session, or single-use correlation | A correlated backend accepts an uninitiated or mismatched callback, Telegram accepts a callback with an invalid HMAC or excessive age, or Facebook Limited Login accepts an ID token with an invalid provider signature, identity claim, or time claim | Security-critical | `(documented)` |
| An OpenID backend accepts a positive assertion only when it matches backend-scoped discovery state from the initiating or provider-authenticated restored browser session; generic OpenID remains provider-selectable, while fixed-provider callbacks and verified signing endpoints must additionally match the exact HTTPS endpoint discovered at initiation | An uninitiated or cross-session OpenID assertion reaches the pipeline, discovery state crosses backend namespaces, or a cleartext or foreign-provider assertion authenticates under a fixed backend | Security-critical | `(documented)` |
| OIDC/JWT and SAML identity assertions are used only after the backend-required signature, issuer, audience, time, nonce/request, subject, and destination checks succeed | Forged or misdirected assertion authenticates or links an account | Security-critical | `(documented)` |
| An authenticating provider identity is bound by backend namespace and a non-empty stable provider identifier; conflicting migration evidence always fails closed, while missing evidence fails except for the audited compatibility transitions documented in section 5a | One provider identity authenticates as a different local user outside the documented missing-evidence exception, or two identities collapse onto one association | Security-critical | `(documented)` |
| Bundled mutable-identifier exceptions do not independently authenticate a remote provider identity: Drip, Last.fm, and Mixcloud are association-only, while EmailAuth and UsernameAuth require application-supplied credential and validation policy | A mutable remote identifier creates or authenticates a local user through an association-only backend, or a legacy backend authenticates without the application's required validation | Security-critical | `(documented)` |
| Association-only flows and their partial resumes are bound by core to the initiating authenticated local user; ordinary linking has the same property when the framework preserves that user through callback; disconnection acts on the authenticated user supplied by the integration | An attacker links to or disconnects from another user's account under the stated integration conditions | Security-critical | `(documented)` |
| An Odnoklassniki iframe app launch received in an authenticated local session proceeds only when its validated OK identity is already associated with that same user | An uncorrelated launch creates or changes an association for the authenticated local user | Security-critical | `(documented)` |
| External partial resumes require ownership or the explicit confirmation path before external request data continues the saved flow; an authenticated confirmer must match the initiating local user, and confirmation never replaces the partial's stored user | A resume link authenticates the recipient into an attacker-selected flow without confirmation, or binds the saved provider identity to a different authenticated local user | Security-critical | `(documented)` |
| With redirect sanitization enabled and trusted allowlists, request-derived HTTP(S) redirects use an allowed host and scheme; private-use redirects use an explicitly allowed scheme | Successful flow redirects to an attacker-controlled destination outside those conditions | Security-critical | `(documented)` |
| With HTTPS endpoints, TLS verification enabled, and trusted endpoint configuration, provider credentials and responses are exchanged through the configured authenticated TLS channel | Network attacker reads credentials or substitutes identity data | Security-critical | `(maintainer)` |
| Default user-detail updates do not overwrite protected identity and authorization-sensitive local fields | Provider profile data changes local IDs, password, activity, staff, superuser, username, or email unexpectedly | Security-critical when it changes authentication or authorization; otherwise correctness | `(documented)` |
| Malformed or rejected provider data does not establish a local authenticated identity; supported failure paths raise social-auth authentication exceptions | Invalid data authenticates a user | Security-critical; exception taxonomy mistakes without identity impact are correctness-only | `(documented)` |

These properties concern identity integrity and credential confidentiality. The
absence of a crash, slowdown, provider outage, or generic parsing exception is
not independently a claimed security property unless it causes one of the
identity-flow violations above. (maintainer)

## 9. Security properties not provided

- social-auth-core does not validate the application's Host or forwarded
  headers. URL construction is not a Host-header security boundary; the proxy
  and framework must enforce that boundary. (documented)
- Redirect sanitization is for post-flow application redirects. It is not a
  general URL safety, SSRF, or egress-control mechanism. (maintainer)
- For an explicitly allowed private-use redirect scheme, sanitization validates
  the scheme but does not claim that the URI's host-like component is approved.
  (maintainer)
- Transport confidentiality is not provided for an operator-configured
  cleartext HTTP endpoint, even when `VERIFY_SSL` is enabled. (maintainer)
- OAuth state, OIDC nonce, PKCE, and SAML request correlation address different
  protocol threats. Enabling one is not a substitute for the checks required by
  the others. Telegram's signed callback authenticates its data and age but does
  not provide browser-session binding or single-use replay protection. Facebook
  Limited Login authenticates the provider-signed ID token and validates its
  applicable identity and time claims, but its direct token flow intentionally
  does not enforce nonce, browser-session binding, or single-use replay
  protection. An Odnoklassniki iframe app launch likewise has no initiation,
  browser-session binding, age limit, or single-use protection; core prevents it
  from creating a new association in an authenticated local session, but an
  anonymous session can still accept a replayed valid launch. (maintainer)
- A valid provider signature proves that the configured provider made a claim;
  it does not prove the claim is true in the physical world or prevent that
  provider from impersonating identities in its namespace. (maintainer)
- Provider email, display name, username, groups, and other profile attributes
  are not stable account identifiers or local authorization facts merely because
  they arrived in an authenticated provider response. Email-based association
  requires the integrator's explicit policy and verification. Audited built-in
  legacy transitions may accept missing migration evidence by default and do
  not guarantee continuous ownership against the documented first-login race;
  a report showing only that accepted race concerns a disclaimed property.
  (documented)
- Token refresh and revocation helpers do not guarantee provider-side logout,
  immediate revocation, or deletion of every provider session. (documented)
- Stored tokens, partials, nonces, associations, and validation codes are not
  encrypted or protected from a compromised application database by the core
  abstraction. (maintainer)
- The library does not provide rate limiting, abuse detection, bot prevention,
  or quantitative resistance to oversized or pathological input. (maintainer)
- The library cannot sandbox or defend against custom code executing in the
  application process. (maintainer)
- Constant-time comparison at selected signature, hash, and state checks is not
  a general side-channel guarantee for the complete authentication flow.
  (maintainer)

## 10. Downstream responsibilities

Integrators must:

- Use supported releases and report suspected violations privately through the
  [security policy](https://github.com/python-social-auth/social-core/security/policy).
  (documented)
- Expose begin, callback, association, disconnection, and partial-resume routes
  through a framework integration that provides the required session, login,
  CSRF, and authenticated-user semantics. Preserve the initiating authenticated
  user through ordinary account-linking callbacks, and reject or restart a
  pending flow if that principal changes. Add application-level initiation and
  single-use binding before using Telegram, Facebook Limited Login, or the
  Odnoklassniki iframe app where login-CSRF or replay protection is required.
  Use the state-bound Odnoklassniki OAuth2 flow for account linking. (maintainer)
- Validate Host and forwarded headers, terminate HTTPS securely, and configure
  canonical callback URLs. See
  [Security considerations](https://python-social-auth.readthedocs.io/en/latest/security.html).
  (documented)
- Protect client secrets, private keys, access and refresh tokens, session data,
  associations, nonces, email codes, and partial records in configuration and
  storage. Preserve the original trust classification of request and provider
  values stored inside those records. (maintainer)
- Configure only intended HTTPS provider endpoints, issuers, signing keys,
  certificates, algorithms, proxies, redirect hosts, and redirect schemes.
  (maintainer)
- Preserve protocol validation and the security-relevant ordering of custom
  pipelines. Treat custom backends, strategies, storage, and pipeline functions
  as security-sensitive application code. See
  [Backend implementation](https://python-social-auth.readthedocs.io/en/latest/backends/implementation.html)
  and [Pipelines](https://python-social-auth.readthedocs.io/en/latest/pipeline.html).
  (documented)
- Use stable provider identifiers and plan migrations according to
  [Identifier migration](https://python-social-auth.readthedocs.io/en/latest/configuration/identifier-migration.html).
  Set `ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION` to `False` when the audited
  compatibility defaults' missing-evidence race is unacceptable. (documented)
- Decide which provider attributes are trusted for user creation, profile
  updates, groups, authorization, email association, and account recovery.
  (maintainer)
- Apply request-body, callback, concurrency, and rate limits appropriate for the
  deployment, and constrain outbound network access where required. (maintainer)

## 11. Known misuse patterns

- Selecting a mutable email, username, UPN, or display name as `ID_KEY` for an
  authenticating provider backend can bind a recycled or renamed provider
  identity to the wrong local account. Use the provider's stable identifier;
  association-only and application-validated legacy backends have the narrower
  conditions documented in sections 5a and 8. (documented)
- Relying on an audited unverified legacy-identifier migration default, or
  explicitly enabling unverified migration elsewhere, treats compatibility as
  sufficient when evidence is missing and accepts a first-login race. Require
  evidence, recovery, or authenticated linking for sensitive deployments.
  (documented)
- Adding `associate_by_email` without an explicit verified-email and account
  recovery policy can merge unrelated accounts. It is intentionally absent from
  the default pipeline. (documented)
- Reordering or removing state, identity, policy, association, or partial-flow
  steps can turn validated data into an unbound authentication decision.
  (maintainer)
- Trusting request-derived endpoint, issuer, redirect, algorithm, or pipeline
  configuration turns trusted settings into an attacker-controlled boundary.
  (maintainer)
- Disabling redirect sanitization or TLS/assertion validation for convenience
  removes the corresponding guarantees in section 8. (maintainer)
- Adding the debug pipeline in production prints authentication responses and
  pipeline data, which can include credentials and personal data. (maintainer)
- Treating provider group or profile claims as local authorization without an
  explicit mapping and lifecycle policy delegates more authority to the provider
  than authentication alone requires. (maintainer)

## 11a. Known non-findings

- Outbound HTTP requests to operator-configured provider, discovery, JWKS,
  token, user-info, refresh, or revocation endpoints are intended behavior. A
  report is not SSRF merely because such a request exists; it must show that an
  in-scope adversary controls the destination despite the section 6 trust
  classification. (maintainer)
- Redirecting the browser to a configured provider authorization endpoint is the
  purpose of the library and is distinct from accepting an untrusted completion
  redirect. (maintainer)
- Protocol-mandated legacy hashes are not password hashing or a claim that the
  hash is collision-resistant. A report must show a break in the protocol's
  authentication property rather than only the presence of a legacy hash name.
  (maintainer)
- Abstract methods that delegate session, storage, login, templates, or email to
  a framework integration are not missing authorization checks by themselves;
  those checks belong at the documented integration boundary. (maintainer)
- Debug-pipeline output is explicit opt-in diagnostic behavior. Enabling it with
  production data is the misuse described in section 11, not a default data
  disclosure. (maintainer)
- Findings confined to tests, CI, packaging scripts, generated files, or static
  artwork are outside the runtime scope in section 3. (maintainer)

## 12. Conditions that change this model

Review this model when a release adds a protocol family, public flow entry
point, deployment mode, input format, network or filesystem effect, storage or
strategy responsibility, security-relevant default, or component promoted into
runtime scope. Also review it when the existing documentation changes a trust
or security statement. Internal refactoring that preserves these interfaces and
properties does not require a model revision. A release containing this file is
evaluated under its shipped model; a release without one is evaluated against
its published documentation and security policy without applying this model's
triage dispositions retroactively. (maintainer)

Any report that cannot be routed to exactly one disposition in section 13 is a
`MODEL-GAP`. The model must be revised instead of resolving such a report using
an undocumented, one-off assumption. (maintainer)

## 13. Triage dispositions

Apply the dispositions in order and stop at the first match. First, classify a
demonstrated violation of section 8 by an in-scope adversary under the supported
posture as `VALID`. Maintainers may instead elect `VALID-HARDENING` for a
section 11 misuse that does not violate section 8; that explicit election takes
precedence over the remaining non-valid dispositions. Otherwise use
`KNOWN-NON-FINDING`, `OUT-OF-MODEL: unsupported-component`,
`OUT-OF-MODEL: non-default-build`, `OUT-OF-MODEL: trusted-input`,
`OUT-OF-MODEL: adversary-not-in-scope`, and
`BY-DESIGN: property-disclaimed`, in that order. Use `MODEL-GAP` only if none
applies. Thus an exact section 11a pattern takes precedence over a broader
component exclusion, and an explicit security-weakening configuration takes
precedence over the fact that settings are trusted. The `trusted-input`
disposition follows a value's origin and cannot be selected merely because
trusted storage returned a persisted attacker-controlled value. (maintainer)

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | An in-scope adversary and input violate a property the project claims | Sections 6, 7, and 8 |
| `VALID-HARDENING` | No section 8 property is violated, but a section 11 misuse is easy enough that maintainers elect to harden it | Section 11 |
| `KNOWN-NON-FINDING` | The report matches a documented recurring false positive | Section 11a |
| `OUT-OF-MODEL: unsupported-component` | The finding is confined to a component excluded from runtime scope | Section 3 |
| `OUT-OF-MODEL: non-default-build` | The finding requires explicit security-weakening configuration | Section 5a |
| `OUT-OF-MODEL: trusted-input` | Exploitation requires control over an input classified as trusted | Section 6 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Exploitation requires a capability excluded from the adversary model | Section 7 |
| `BY-DESIGN: property-disclaimed` | The report concerns a property explicitly not provided | Section 9 |
| `MODEL-GAP` | The report cannot be routed to another disposition | Section 12; revise this model |

The disposition set is closed. Severity and disclosure handling for a `VALID`
report depend on the violated property and concrete impact; the table is not a
substitute for vulnerability assessment. (maintainer)

## 14. Open questions for maintainers

Not applicable. This accepted version contains no inferred claims. New
uncertainty discovered after acceptance is a `MODEL-GAP` and reopens this
section in the next revision. (maintainer)

## 15. Machine-readable companion

Not applicable. The Markdown document is canonical and no machine-readable
triage consumer is currently maintained. Add a derived sidecar only when a
consumer and synchronization process exist. (maintainer)
