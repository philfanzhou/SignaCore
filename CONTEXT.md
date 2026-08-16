# Identity and Access

SignaCore is the authentication authority for a set of services that share one account population.
It authenticates people, issues signed tokens scoped to a registered application, and owns the
credentials and admission records that decide who may sign in where. It does not own business roles
or permissions; those are supplied by the applications themselves.

For the technology stack and canonical deployment identifiers, see
[docs/overview/Context.md](./docs/overview/Context.md). This file is the glossary.

## Language

### Identities

**Account**:
The authenticated subject. One person has one account regardless of how many applications they use
or how many credentials are bound to it.
_Avoid_: user, profile, identity

**Credential**:
Something that proves control of an account — a password, an LDAP directory entry, a phone number
reachable by OTP, a WeChat identity. An account may hold several.
_Avoid_: login method, auth provider

**Application**:
A registered consumer of this service, identified by an AppId and authenticated by an AppSecret. It
receives tokens and may register a callback. A deployment's user-facing site, staff site, and
back office are three applications, not one.
_Avoid_: client, service, portal, tenant

### Authentication

**Grant**:
A way of obtaining tokens, named by the grant type presented at the token endpoint — password, sms,
wechat_code, ldap, refresh_token.
_Avoid_: login flow, auth mode

**Admission**:
An application-scoped record that a specific credential is allowed to sign in to a specific
application. Admission is per application: holding a credential does not by itself grant entry
anywhere. Each admission carries an approval source recording how it came to exist.
_Avoid_: access, permission, authorization, entitlement

**Callback**:
An HTTP endpoint an application registers so this service can ask it, at token issuance, what claims
that application wants embedded for the account. It is how business roles reach a token without this
service knowing what they mean.
_Avoid_: webhook, claims provider

### Tokens

**Refresh token**:
A long-lived secret bound to one account and one application, exchangeable for a new access token.
The application binding is part of its identity, not an annotation on it — see
[ADR 0003](./docs/adr/0003-cross-application-refresh-grant.md).
_Avoid_: session token

**Cross-application refresh grant**:
A refresh grant in which the presenting application is not the one the refresh token was issued to.
It is permitted only along an exchange trust, mints rather than rotates, and is single-hop.
_Avoid_: SSO, single sign-on, token exchange

The term "single sign-on" is deliberately rejected: in OAuth it denotes session reuse at an
authorization endpoint, a surface this service does not have. Applications outside this context may
call the user-visible feature SSO; inside it, the mechanism is a cross-application refresh grant.

**Exchange trust**:
An administered, directed statement that one application accepts refresh tokens issued to another.
It scopes authentication only; it says nothing about what the resulting session may do.
_Avoid_: trust group, federation, application group
