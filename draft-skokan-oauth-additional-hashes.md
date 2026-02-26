---
title: "Additional Hash Algorithms for OAuth 2.0 PKCE and Proof-of-Possession"
abbrev: "Additional Hashes for OAuth PoP and PKCE"
category: std

docname: draft-skokan-oauth-additional-hashes-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - oauth
 - pkce
 - dpop
 - mtls
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  github: "panva/draft-oauth-additional-hashes"

author:
 -
    fullname: Filip Skokan
    organization: Okta
    email: panva.ip@gmail.com

normative:
  RFC7636:
  RFC7638:
  RFC8414:
  RFC8705:
  RFC9449:
  RFC9728:
  OpenID.Discovery:
    title: OpenID Connect Discovery 1.0 incorporating errata set 2
    target: https://openid.net/specs/openid-connect-discovery-1_0-errata2.html
    date: December 15, 2023
    author:
      - ins: N. Sakimura
      - ins: J. Bradley
      - ins: M. Jones
      - ins: E. Jay

informative:
  cnsafaq:
    title: "The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ"
    author:
      org: National Security Agency
    date: 2024-12
    target: https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
...

--- abstract

This document defines SHA-384 as an additional hash algorithm option
for OAuth 2.0 Proof Key for Code Exchange (PKCE), Demonstrating Proof
of Possession (DPoP), and mutual-TLS certificate-bound access tokens.
These mechanisms currently mandate the use of SHA-256.


--- middle

# Introduction

Several OAuth 2.0 mechanisms exclusively mandate the use of SHA-256:
Proof Key for Code Exchange (PKCE) {{RFC7636}}, Demonstrating Proof of
Possession (DPoP) {{RFC9449}}, and mutual-TLS certificate-bound access
tokens {{RFC8705}}.

Security policies, such as the US Commercial National Security
Algorithm (CNSA 2.0) Suite {{cnsafaq}}, prohibit the use of SHA-256 and
mandate SHA-384 as the minimum acceptable hash algorithm. This
prevents the deployment of these OAuth 2.0 mechanisms in such
environments.

This document addresses this gap by defining SHA-384 alternatives
for each of these mechanisms. For PKCE, a new `S384` code challenge
method is defined. For mutual-TLS certificate-bound access tokens,
a new `x5t#S384` confirmation method is defined. For DPoP, this
document defines SHA-384 alternatives for the JWK Thumbprint
confirmation method (`jkt#S384`) and the access token hash claim
(`ath#S384`), as well as an extensible framework for DPoP
authorization code binding and access token hash algorithm
negotiation.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

All references to "CNSA 2.0" in this document refer to CNSA 2.0
{{cnsafaq}}, unless stated otherwise.


# SHA-384 PKCE Code Challenge Method

## S384 Code Challenge Method {#S384}

This document defines a new code challenge method for use with
PKCE {{RFC7636}}. The client creates a code challenge derived from
the code verifier by using the following transformation on the code
verifier:

S384:
: code_challenge = BASE64URL(SHA-384(ASCII(code_verifier)))

The server-side verification of the code verifier follows
{{Section 4.6 of RFC7636}}, using SHA-384 as the hash algorithm.

## Authorization Server Metadata {#as-metadata}

An Authorization Server that supports the `S384` code challenge
method MUST advertise its support by including `S384` in the
`code_challenge_methods_supported` metadata parameter value, as
defined in OAuth 2.0 Authorization Server Metadata {{RFC8414}} or
OpenID Connect Discovery 1.0 {{OpenID.Discovery}}.

A Client intending to use the `S384` code challenge method MUST
first confirm that the Authorization Server supports it by checking
the `code_challenge_methods_supported` metadata value. A Client MUST
NOT use the `S384` code challenge method if the Authorization Server
does not advertise support for it.


# DPoP Authorization Code Binding Methods

## dpop_jkt_method Authorization Request Parameter {#dpop-jkt-method}

RFC 9449 {{RFC9449}} defines the `dpop_jkt` authorization request
parameter as the JWK Thumbprint {{RFC7638}} of the DPoP public key
using SHA-256.

This document defines the `dpop_jkt_method` authorization request
parameter, sent alongside `dpop_jkt`, to indicate the hash algorithm
used to compute the JWK Thumbprint. The following method values are
defined:

S256:
: JWK Thumbprint {{RFC7638}} using SHA-256, as originally
  defined in {{Section 10 of RFC9449}}.

S384:
: JWK Thumbprint {{RFC7638}} using SHA-384.

When `dpop_jkt_method` is absent from the authorization request, the
Authorization Server MUST assume the value `S256`.

The value of `dpop_jkt` MUST be computed using the hash algorithm
indicated by `dpop_jkt_method`.

## DPoP Authorization Server Metadata {#dpop-as-metadata}

This document defines the `dpop_jkt_methods_supported` Authorization
Server metadata parameter. Its value is a JSON array containing the
`dpop_jkt_method` values that the Authorization Server supports.

An Authorization Server that supports `dpop_jkt_method` values
beyond `S256` MUST advertise its support by including the supported
values in the `dpop_jkt_methods_supported` metadata parameter.

A Client intending to use a `dpop_jkt_method` value other than
`S256` MUST first confirm that the Authorization Server supports it
by checking the `dpop_jkt_methods_supported` metadata value. A
Client MUST NOT use a `dpop_jkt_method` value that the Authorization
Server does not advertise support for.


# SHA-384 DPoP Hash Algorithms

## jkt#S384 Confirmation Method {#jkt-S384}

RFC 9449 {{RFC9449}} defines the `jkt` confirmation method member
for binding access tokens to a DPoP public key using a SHA-256
JWK Thumbprint {{RFC7638}}.

This document defines an analogous confirmation method member
`jkt#S384` that uses SHA-384 as the hash algorithm:

jkt#S384:
: The value is the base64url encoding of the JWK
  Thumbprint {{RFC7638}} computed using SHA-384 of the DPoP
  public key (in JWK format) to which the access token is bound.

When using `jkt#S384`, the Authorization Server computes the
SHA-384 JWK Thumbprint of the DPoP public key and includes the
result as the `jkt#S384` member of the `cnf` claim in the access
token (for JWT access tokens) or associates it with the token
for later retrieval via token introspection.

The Resource Server MUST compute the SHA-384 JWK Thumbprint of
the DPoP public key and compare it with the `jkt#S384` value in
the `cnf` claim. If the values do not match, the Resource Server
MUST reject the request.

The choice of `jkt#S384` over `jkt` is a deployment decision
based on the Resource Server configuration at the Authorization
Server.

## ath#S384 Access Token Hash {#dpop-ath}

RFC 9449 {{RFC9449}} defines the `ath` claim in the DPoP proof JWT
as the base64url-encoded SHA-256 hash of the ASCII encoding of the
access token value.

This document defines an analogous claim `ath#S384` that uses
SHA-384 as the hash algorithm:

ath#S384:
: The value is the base64url encoding of the SHA-384 hash of
  the ASCII encoding of the associated access token's value.

When used, `ath#S384` is included in the DPoP proof JWT in place
of `ath`.

A Client that used a `dpop_jkt_method` value of `S384` during the
authorization request MUST use `ath#S384` in DPoP proofs sent to
Resource Servers.

A Resource Server MAY signal the required access token hash method
by including the `ath_method` parameter in the `WWW-Authenticate:
DPoP` challenge. The value of `ath_method` is the name of the claim
the Client MUST use: `ath` for SHA-256 or `ath#S384` for SHA-384.
When `ath_method` is absent, the Client MUST use `ath`.

## Resource Server Metadata {#dpop-rs-metadata}

This document defines the `dpop_ath_methods_supported` Resource
Server metadata parameter {{RFC9728}}. Its value is a JSON array
containing the access token hash claim names that the Resource
Server supports. Defined values are `ath` and `ath#S384`.

When this metadata parameter is absent, the Client MUST assume
that the Resource Server supports only `ath`.


# SHA-384 Mutual-TLS Certificate Hash {#mtls}

## x5t#S384 Confirmation Method {#x5t-S384}

RFC 8705 {{RFC8705}} defines the `x5t#S256` confirmation method
member for binding access tokens to a client certificate using a
SHA-256 hash of the DER-encoded X.509 certificate.

This document defines an analogous confirmation method member
`x5t#S384` that uses SHA-384 as the hash algorithm:

x5t#S384:
: The value is a base64url-encoded SHA-384 hash of the
  DER encoding of the X.509 certificate.

When using `x5t#S384`, the Authorization Server computes the
SHA-384 hash of the client certificate presented during mutual-TLS
and includes the result as the `x5t#S384` member of the `cnf`
claim in the access token (for JWT access tokens) or associates
it with the token for later retrieval via token introspection.

The Resource Server MUST compute the SHA-384 hash of the client
certificate presented during mutual-TLS and compare it with the
`x5t#S384` value in the `cnf` claim. If the values do not match,
the Resource Server MUST reject the request.

The choice of `x5t#S384` over `x5t#S256` is a deployment decision
based on the Resource Server configuration at the Authorization
Server.


# Security Considerations

The `S384` code challenge method provides the same structural
security properties as `S256`. It is a one-way transformation of
the code verifier that prevents an attacker who intercepts the
authorization code from computing the code verifier needed to exchange
it for tokens.

The `jkt#S384` confirmation method, `dpop_jkt_method` parameter,
and `ath#S384` claim provide the same structural security properties
as their SHA-256 counterparts defined in DPoP {{RFC9449}}. The
authorization code binding via `dpop_jkt` and the access token
binding via `ath` remain intact regardless of the hash algorithm
used.

SHA-384 provides a 192-bit collision resistance and 384-bit preimage
resistance, exceeding the 128-bit and 256-bit levels provided by
SHA-256. The use of SHA-384 is suitable for deployments with elevated
security requirements.

Deployments that do not have specific requirements mandating SHA-384
do not need to migrate away from the established SHA-256 based
mechanisms.


# IANA Considerations

## PKCE Code Challenge Method Registration

This document requests registration of the following value in the
"PKCE Code Challenge Methods" registry established by {{Section 6.2 of
RFC7636}}:

Code Challenge Method Parameter Name:
: `S384`

Change Controller:
: IETF

Specification Document(s):
: {{S384}} of this document


## DPoP Authorization Code Binding Methods Registry {#dpop-binding-registry}

This document establishes the "DPoP Authorization Code Binding
Methods" registry for `dpop_jkt_method` values.

New entries are registered using the Specification Required policy
{{!RFC5226}}.

The initial contents of the registry are:

Method Name:
: `S256`

Change Controller:
: IETF

Specification Document(s):
: {{Section 10 of RFC9449}}

Method Name:
: `S384`

Change Controller:
: IETF

Specification Document(s):
: {{dpop-jkt-method}} of this document

## OAuth Parameters Registrations

This document requests registration of the following value in the
"OAuth Parameters" registry established by {{!RFC6749}}:

Parameter Name:
: `dpop_jkt_method`

Parameter Usage Location:
: authorization request

Change Controller:
: IETF

Specification Document(s):
: {{dpop-jkt-method}} of this document

## OAuth Authorization Server Metadata Registration

This document requests registration of the following value in the
"OAuth Authorization Server Metadata" registry established by
{{RFC8414}}:

Metadata Name:
: `dpop_jkt_methods_supported`

Metadata Description:
: JSON array containing a list of the `dpop_jkt_method`
  values supported by the Authorization Server

Change Controller:
: IETF

Specification Document(s):
: {{dpop-as-metadata}} of this document

## JWT Claims Registration

This document requests registration of the following value in the
"JSON Web Token Claims" registry established by {{!RFC7519}}:

Claim Name:
: `ath#S384`

Claim Description:
: The base64url-encoded SHA-384 hash of the ASCII encoding
  of the associated access token's value

Change Controller:
: IETF

Specification Document(s):
: {{dpop-ath}} of this document

## OAuth Protected Resource Metadata Registration

This document requests registration of the following value in the
"OAuth Protected Resource Metadata" registry established by
{{RFC9728}}:

Metadata Name:
: `dpop_ath_methods_supported`

Metadata Description:
: JSON array containing a list of the access token hash
  claim names supported by the Resource Server

Change Controller:
: IETF

Specification Document(s):
: {{dpop-rs-metadata}} of this document

## JWT Confirmation Methods Registrations

This document requests registration of the following values in the
"JWT Confirmation Methods" registry established by {{!RFC7800}}:

Confirmation Method Value:
: `x5t#S384`

Confirmation Method Description:
: X.509 Certificate SHA-384 Thumbprint

Change Controller:
: IETF

Specification Document(s):
: {{x5t-S384}} of this document

Confirmation Method Value:
: `jkt#S384`

Confirmation Method Description:
: JWK SHA-384 Thumbprint

Change Controller:
: IETF

Specification Document(s):
: {{jkt-S384}} of this document


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
