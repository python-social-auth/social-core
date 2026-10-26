# Threat model

## Purpose and applicability

social-auth-core is an in-process authentication library. This model records
its runtime security contract and vulnerability triage policy. Configuration,
integration, upgrade, and recovery instructions belong in the
[project documentation](https://python-social-auth.readthedocs.io/en/latest/security.html).
The framework integration supplies additional boundaries; see the
[Django integration model](https://github.com/python-social-auth/social-app-django/blob/master/THREAT_MODEL.md).

This model is versioned with the package. Evaluate releases against the model
shipped in their source distribution or repository tag, rather than the current
branch. For releases without a model, use their published documentation and
security policy; do not apply later triage dispositions retroactively. Report
suspected violations privately through the
[security policy](https://github.com/python-social-auth/social-core/security/policy).

## Scope, actors, and trust boundaries

All shipped runtime Python code is in scope: public authentication,
association, disconnection, refresh, and partial-resume operations; pipelines;
protocols and bundled backends, including installed extras; and the shared
strategy and storage contracts. Tests, CI, packaging utilities, generated files,
and static artwork are outside runtime scope. Supply-chain, release-signing,
and repository-administration controls are outside this model.

In-scope attackers are unauthenticated remote clients and authenticated users
attempting to affect other accounts. They can control browser requests,
callback parameters, their own provider accounts and profile attributes;
replay observed inputs; and initiate concurrent or interrupted flows. Provider
responses are untrusted until protocol validation. Malformed, replayed, or
inconsistent responses must not bypass the applicable identity checks.

The application process, operator configuration, conforming strategy/storage
implementations, and custom backend and pipeline code are trusted. Attackers
controlling these components, the host, signing credentials, TLS trust roots,
or protected storage are outside the model. A configured provider is trusted
to assert identities within its namespace. Its dishonesty is outside the model,
but its responses must not acquire authority in another namespace or bypass
local flow and user bindings.

The normal flow crosses these boundaries:

1. An untrusted browser request enters a framework route and strategy.
2. Core initiates the protocol and, where supported, records correlation before
   redirecting to the configured provider.
3. Untrusted callback and provider data undergo the backend's protocol checks.
4. The pipeline binds the validated provider identity to a local user through
   trusted storage.
5. The framework establishes the login session and returns a validated redirect.

| Input or surface | Trust and responsibility |
| --- | --- |
| Browser parameters, callbacks, resume links, and provider responses | Untrusted; validation precedes the security decision consuming them |
| Settings, endpoints, keys, algorithms, proxies, and extension code | Trusted operator/application input; not authority supplied by request data |
| Authenticated local user and session context | Supplied by the integration; preserve initiating flow bindings |
| Storage record identity, ownership, and integrity metadata | Trusted under the storage contract |
| Request fields, claims, redirects, and pipeline values saved in sessions/storage | Retain their original provenance; persistence does not validate contents |

Flow findings must be reachable through a public operation, parser findings
through callback/provider data, and HTTP findings through a bundled backend or
intentionally user-selectable protocol input. Defects solely in custom
integrations are outside this model; core interface-contract defects are in scope.

## Assumptions and security properties

The environment supplies a supported runtime and dependencies with their normal
cryptographic, TLS, parsing, and validation behavior, accurate enough clocks,
and isolated request contexts. The framework supplies correct request, session,
login, CSRF, Host, trusted-proxy, and required response-header semantics. Storage supplies integrity,
uniqueness, expiry persistence, tenant isolation, and atomic identity/nonce
claims across workers. Extensions must preserve these contracts.

The supported posture retains required protocol checks, trusted HTTPS endpoints
and TLS verification, redirect sanitization with restricted destinations,
protected local fields, finite validation-code expiry, and security-relevant
pipeline ordering. Backend defaults may differ by protocol; optional PKCE for a
confidential client is not automatically unsupported. Explicitly weakening a
required check removes its corresponding guarantee. See
[Settings](https://python-social-auth.readthedocs.io/en/latest/configuration/settings.html)
and the selected backend's documentation.

| Property | Security violation |
| --- | --- |
| Correlated protocols accept callbacks only for the initiating flow/session after required state, nonce, or request checks; OAuth2 login state expires and is consumed once before token exchange | An uninitiated, mismatched, expired, or reused transaction authenticates or links an account |
| OpenID assertions match a one-use signed transaction and backend-scoped discovery state in the initiating browser session; fixed providers bind to the exact discovered HTTPS endpoint | Unsolicited, cross-session, stale, or foreign-provider assertions authenticate under the backend namespace |
| Identity assertions pass backend-required signature, issuer, audience, time, nonce/request, subject, and destination checks | Forged or misdirected assertions authenticate or link an account |
| Provider identities use a non-empty stable identifier in their backend namespace; missing migration evidence fails except for the compatibility exceptions below, and conflicting evidence always fails | Distinct identities collapse onto one association or access another account outside the exceptions below |
| Core binds association-only flows and partial resumes to the initiating authenticated user; ordinary linking has this property when the integration preserves that user through callback; disconnection acts on the integration's authenticated user | A flow links to or disconnects another user's account |
| External partial resumes require ownership or explicit confirmation; an authenticated confirmer matches the initiating user and cannot replace the saved user | A link resumes an attacker-selected flow without confirmation or binds it to a different authenticated user |
| Sanitized request-derived HTTP(S) redirects use allowed hosts/schemes; approved private-use schemes are checked by scheme | Completion escapes the configured redirect boundary |
| Request-derived redirect values are destinations, not references to unrelated settings | A redirect discloses a sensitive configuration value |
| Provider credentials and responses use the configured authenticated TLS channel | A network attacker reads credentials or substitutes identity data under the supported transport posture |
| Default profile updates preserve protected identity and authorization fields; configured authentication restrictions require matching provider data under the documented policy | Provider data changes protected account authority or bypasses an access restriction |
| Malformed or rejected provider input does not establish an authenticated identity; supported rejection paths use social-auth authentication exceptions | Invalid data authenticates a user |

Identity, flow, policy, redirect, and transport violations are security-critical
when they cross the stated account or confidentiality boundary. Other profile
correctness, exception taxonomy, and response errors are ordinary defects
without such impact. Crashes, slowdowns, outages, or generic parsing exceptions
alone do not violate a claimed identity-flow property.

### Necessary exceptions

These exceptions qualify the properties above; procedures belong in the linked
documentation.

- **Opt-in IdP-initiated SAML:** When explicitly enabled, unsolicited signed
  responses have no initiating browser request to correlate. Anonymous browsers
  can accept a valid assertion posted by another party; deployments requiring
  login CSRF protection must keep this option disabled.
- **Uncorrelated signed flows:** [Telegram](https://python-social-auth.readthedocs.io/en/latest/backends/telegram.html)
  validates callback HMAC and age; [Facebook Limited Login](https://python-social-auth.readthedocs.io/en/latest/backends/facebook_limited_login.html)
  validates the provider signature and applicable identity/time claims but does
  not enforce nonce. Neither supplies initiation, browser-session binding, or
  single-use protection. [VK](https://python-social-auth.readthedocs.io/en/latest/backends/vk.html)
  and [Odnoklassniki](https://python-social-auth.readthedocs.io/en/latest/backends/odnoklassnikiru.html)
  iframe launches likewise lack those bindings and an age limit. They validate
  launch signatures and provider identity; Odnoklassniki also confirms the user
  through the supplied provider session. In an authenticated local session,
  these iframe flows accept only an identity already associated with that user;
  anonymous launches can still accept a valid replay. Applications requiring
  stronger binding must supply it.
- **Mutable-identifier backends:** Drip, Last.fm, and Mixcloud are
  association-only and must not independently create or authenticate a local
  user. EmailAuth and UsernameAuth rely on application credential and validation
  policy rather than independently proving a remote identity.
- **Missing ownership evidence:** Audited built-in legacy identifier transitions
  may accept missing evidence by default, with a first-login race. These
  supported compatibility defaults do not prove continuous ownership. Explicit
  unverified migration elsewhere weakens security; conflicting evidence still
  fails. Configured stable identifiers are outside the audited exception;
  missing or incorrectly backfilled key provenance requires operator review.
  See [Identifier migration](https://python-social-auth.readthedocs.io/en/latest/configuration/identifier-migration.html).
  [EVE Online](https://python-social-auth.readthedocs.io/en/latest/backends/eveonline.html)
  similarly accepts the next valid owner hash for an association lacking one;
  a transfer before that backfill cannot be detected. Later changes fail closed.

## Limits and downstream responsibilities

Core does not run an HTTP service or supply application authorization, account
recovery, MFA, session-cookie policy, route-level CSRF, TLS termination, Host
validation, or trusted-proxy configuration. Integrations must supply those
boundaries and preserve the authenticated user across ordinary linking, or
reject and restart the flow when that principal changes. Strategies that return
core-generated HTML must apply the requested response headers.

Operators must protect configuration, tokens, secrets, sessions, and persisted
records. Core does not encrypt them at rest or protect them from a compromised
database. Provider profile values are not stable identifiers, verified email
ownership, or local authorization facts merely because their response was
authenticated. Email association and authorization mappings require explicit
application policy. Custom code cannot be sandboxed by this library.

Redirect sanitization is not general URL safety or SSRF prevention, and an
approved private-use scheme does not imply approval of a host-like component.
Generic OpenID intentionally permits user-selected discovery; applications must
decide whether to expose it and constrain egress when required. Cleartext
endpoints have no transport confidentiality even with TLS verification enabled.
State, nonce, PKCE, and assertion correlation address different threats and are
not interchangeable.

There is no quantitative input-size, rate, CPU, memory, latency, availability,
or complete-flow side-channel guarantee. Deployments supply suitable limits.
Refresh and revocation do not guarantee provider logout or immediate removal of
all provider sessions. Outbound HTTP is intended; Azure workload identity may
read a trusted configured token file. Core may log; the opt-in debug pipeline
prints authentication data. Core does not listen on sockets, spawn processes,
or install signal handlers.

See [Security considerations](https://python-social-auth.readthedocs.io/en/latest/security.html),
[Pipelines](https://python-social-auth.readthedocs.io/en/latest/pipeline.html),
[Strategies](https://python-social-auth.readthedocs.io/en/latest/strategies.html),
and [Storage](https://python-social-auth.readthedocs.io/en/latest/storage.html)
for integration requirements.

## Review and triage

Review the model when changing public flows, protocols, backends, input formats,
network/filesystem effects, deployment modes, strategy/storage responsibilities,
or security defaults, and when documentation changes a trust statement. Edit
it only when a boundary, assumption, property, exception, responsibility, or
triage rule changes or leaves a gap. Fixes restoring an existing guarantee and
internal refactors do not need individual entries.

Known misuse includes mutable account identifiers, unverified migrations,
email association without verification/recovery policy, reordered validation
or association steps, request-controlled configuration, disabled transport or
redirect checks, production debug output, and unreviewed provider-to-local
authorization mappings. These patterns may justify discretionary hardening.

Known non-findings are intended outbound requests to trusted configured
endpoints; redirects to configured authorization endpoints; protocol-mandated
legacy hash names without an authentication break; abstract framework delegation
without a core contract violation; explicit opt-in debug output; and findings
confined to excluded development or presentation files. A destination selected
by an in-scope attacker or default disclosure is not discharged by these patterns.

Apply dispositions in order, stopping at the first match. First accept a
demonstrated violation under the supported posture as `VALID`. Maintainers may
instead elect `VALID-HARDENING` for a known misuse without a property violation;
that election precedes the remaining dispositions. Then apply the remaining
rows in order. Severity and disclosure depend on concrete impact.

| Disposition | Condition |
| --- | --- |
| `VALID` | An in-scope adversary and input violate a claimed property |
| `VALID-HARDENING` | Maintainers elect to harden a known misuse without a property violation |
| `KNOWN-NON-FINDING` | The report matches a known non-finding above |
| `OUT-OF-MODEL: unsupported-component` | The finding is confined to excluded runtime scope |
| `OUT-OF-MODEL: non-default-build` | Exploitation requires explicit security-weakening configuration |
| `OUT-OF-MODEL: trusted-input` | Exploitation requires control of trusted input |
| `OUT-OF-MODEL: adversary-not-in-scope` | Exploitation requires an excluded attacker capability |
| `BY-DESIGN: property-disclaimed` | The property is explicitly not provided |
| `MODEL-GAP` | No disposition applies; revise the model before deciding |

The disposition set is closed. `trusted-input` follows the value's origin;
trusted storage does not make saved attacker-controlled data trusted. An exact
known non-finding precedes broader component exclusion; explicit weakening
precedes settings' trusted status. A report that cannot be routed to exactly
one disposition is a model gap, not grounds for an undocumented assumption.
