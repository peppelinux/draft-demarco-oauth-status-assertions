---
title: "OAuth Status Assertions"
abbrev: "OAuth Status Assertions"
category: info

docname: draft-demarco-oauth-status-assertions-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
keyword:
 - digital credentials
 - revocation
venue:
  github: "peppelinux/draft-demarco-oauth-status-assertions"
  latest: "https://peppelinux.github.io/draft-demarco-oauth-status-assertions/draft-demarco-oauth-status-assertions.html"

author:
 -
    fullname: Giuseppe De Marco
    organization: Dipartimento per la trasformazione digitale
    email: gi.demarco@innovazione.gov.it
 -
    fullname: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
 -
    fullname: Francesco Marino
    organization: Istituto Poligrafico e Zecca dello Stato
    email: fa.marino@ipzs.it

normative:
  RFC2046: RFC2046
  RFC6749: RFC6749
  RFC6838: RFC6838
  RFC7515: RFC7515
  RFC7516: RFC7516
  RFC7517: RFC7517
  RFC7519: RFC7519
  RFC7800: RFC7800
  RFC8152: RFC8152
  RFC8392: RFC8392
  RFC8747: RFC8747
  RFC9126: RFC9126
  OpenID.Core:
    author:
      org: "IANA"
    title: "Media Types"
    target: "https://www.iana.org/assignments/media-types/media-types.xhtml"
  OpenID4VCI:
    author:
      org: "OpenID Foundation"
    title: "OpenID for Verifiable Credential Issuance"
    target: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
  IANA.MediaTypes:
    author:
      org: "IANA"
    title: "Media Types"
    target: "https://www.iana.org/assignments/media-types/media-types.xhtml"
  IANA.JOSE:
    author:
      org: "IANA"
    title: "JSON Object Signing and Encryption (JOSE)"
    target: "https://www.iana.org/assignments/jose/jose.xhtml"
  IANA.JWT:
    author:
      org: "IANA"
    title: "JSON Web Token Claims"
    target: "https://www.iana.org/assignments/jwt/jwt.xhtml"
  IANA.CWT:
    author:
      org: "IANA"
    title: "CBOR Web Token (CWT) Claims"
    target: "https://www.iana.org/assignments/cwt/cwt.xhtml"
  RFC9596: RFC9596
  IANA-HASH-REG:
    title: "IANA - Named Information Hash Algorithm Registry"
    target: "https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg"

informative:
  draft-ietf-oauth-status-list:
    title: draft-ietf-oauth-status-list
    target: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list
  ECHR-ART8:
    title: Article 8 of the European Convention on Human Rights
    target: https://www.echr.coe.int/documents/convention_eng.pdf
  GDPR:
    title: GDPR
    target: https://gdpr-info.eu/
  SD-JWT.VC: I-D.ietf-oauth-sd-jwt-vc
  ISO.mdoc:
    author:
      org: "ISO/IEC JTC 1/SC 17"
    title: "ISO/IEC 18013-5:2021 ISO-compliant driving licence"
  OpenID4VP:
    author:
      org: "OpenID Foundation"
    title: "OpenID for Verifiable Credential Presentation"
    target: "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html"
  RFC6066:
    title: "Transport Layer Security (TLS) Extensions: Extension Definitions"
    target: "https://datatracker.ietf.org/doc/html/rfc6066"


--- abstract

Status Assertion is a signed object that demonstrates the validity status of a
digital credential.
These assertions are periodically provided
to holders, who can present these to verifier along
with the corresponding digital credentials.
The approach outlined in this document
makes the verifier able to check the status,
such as the non-revocation, of a digital credential
without requiring to query any third-party entities.

--- middle

# Introduction

Status Assertions show the status of digital
credentials, whether in JSON Web Tokens (JWT) or CBOR Web Tokens (CWT)
format. Status Assertions function
similarly to OCSP Stapling ([RFC6066]), allowing clients to present to the
relying parties
time-stamped assertions provided by the credential issuer.
The approach outlined in this specification enables the
verification of credentials against revocation without
direct queries to third-party systems,
enhancing privacy, reducing latency, and
faciliting offline verification.

The figure below illustrates the process by which a client,
such as a wallet instance,
requests and obtains a Status Assertion from the credential issuer.

~~~ ascii-art
+-----------------+                              +-------------------+
|                 | Requests Status Assertions   |                   |
|                 |----------------------------->|                   |
| Client          |                              | Credential Issuer |
|                 | Status Assertions            |                   |
|                 |<-----------------------------|                   |
+-----------------+                              +-------------------+
~~~
**Figure 1**: Status Assertion Issuance Flow.

The figure below illustrates the process by which a client
presents the Status Assertion along with the corresponding digital credential.

~~~ ascii-art
+-- ----------------+                             +----------+
|                   | Presents Digital Credential |          |
| Client            | and Status Assertion        | Verifier |
|                   |---------------------------->|          |
+-------------------+                             +----------+
~~~
**Figure 2**: Status Assertion Presentation Flow.

In summary, the credential issuer provides the client with a
Status Assertion, which is linked to a Digital Credential. This enables
the client to present both the digital credential and its
Status Assertion to a verifier as proof of the digital credential's
validity status.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Terminology

This specification uses the terms "End-User", "Entity" as defined by
OpenID Connect Core [OpenID.Core], the term "JSON Web Token (JWT)"
defined by JSON Web Token (JWT) {{RFC7519}},
the term "CBOR Web Token (CWT)" defined in {{RFC8392}}, "Client" as
defined {{RFC6749}}, "Verifiable Presentation" defined in [@OpenID4VP].

Digital Credential:
: A set of one or more claims about a subject made by a Credential Issuer.
Alternative names are "Verifiable Credential" or "Credential".

Holder:
: An entity that possesses Verifiable Credentials and has
control over them to present them to the Verifiers as Verifiable Presentations.

Credential Issuer:
: Entity that is responsible for the issuance of the Digital Credentials.
The Issuer is responsible for the lifecycle of their issued
Digital Credentials and their validity status.

Verifier:
: Entity that relies on the validity of the Digital Credentials presented to it.
This Entity, also known as a Relying Party, verifies the authenticity and
validity of the Digital Credentials, including their revocation status,
before accepting them.

Wallet Instance:
: The digital Wallet in control of a User, also known as Wallet.
It securely stores the User's Digital Credentials. It can present
Digital Credentials to Verifiers
and request Status Assertions from Issuers under the control of the User.
For the purposes of this specification, the Wallet Instance is
considered as a Client.

# Rationale

There are cases where the Verifier only needs
to check the revocation status of a Digital Credential at the time of
presentation, and therefore it should not be allowed to
check the status of a Digital Credential over time due to some
privacy constraints,
in compliance with national privacy regulations.

For instance, consider a scenario where a Verifier's repeated access to a
status list, such as the one defined in
[draft-ietf-oauth-status-list]
to check the revocation status of a Digital Credential could
be deemed as excessive monitoring of the End-User's activities.

This could potentially infringe upon the End-User's right to privacy,
as outlined in
[ECHR-ART8] and
in the the European Union's General Data Protection Regulation
[GDPR],
by creating a detailed profile of the End-User's
Digital Credential status without explicit consent for
such continuous surveillance.

# Requirements

The general requirements for the implementation of Status Assertion are
listed in this section. The Status Assertion:

- SHOULD be presented in conjunction with the Digital Credential.
- MUST include information that links it to the
referenced Digital Credential;
- MUST be timestamped with its issuance datetime,
using a timestamp which is at or after the time of
Digital Credential issuance which it refers;
- MUST contain the expiration datetime after which
the Status Assertion MUST NOT be considered valid anymore,
and the Digital Credential it refers
SHOULD NOT be considered valid anymore. The expiration datetime MUST be
superior to the Status Assertion issuance datetime and it MUST end before
the expiration datetime of the Digital Credential;
- MUST enable the offline use cases by employing validation using
a cryptographic signature and the cryptographic public key of the
Credential Issuer.
- SHOULD NOT contain personal information about the User who owns
the Digital Credential to which the Status Assertion refers.

# Proof of Possession of a Credential

The concept of Proof of Possession (PoP) of a Credential within the
framework of the Status Assertion specification encompasses a broader
perspective than merely possessing the digital bytes of the Credential.

It involves demonstrating rightful control or ownership over the
Credential, which can manifest in various forms depending on the
technology employed and the nature of the Digital Credential itself.
For instance, a Digital Credential could be presented visually (de-visu)
with a personal portrait serving as a binding element.

While this specification does not prescribe any additional methods
for the proof of possession of the Credential, it aims to offer
guidance for concrete implementations utilizing common proof of
possession mechanisms. This includes, but is not limited to:

1. Having the digital representation of the Digital Credential (the bytes).
2. Controlling the confirmation method of the Credential,
using the Credential's `cnf` parameter.

The essence of requiring proof of possession over the Credential
through the confirmation method, such has proving the control of the
cryptographic material related to a Credential, is
to ensure that the entity in possession of the Credential can execute
actions exclusively reserved to the legitimate Holder.
The dual-layered approach of requiring both possession of the
Credential and control over it, reinforces the security and integrity
of the Status Assertion process.
This ensures that the Holder requesting a Status Assertion is indeed
the same Holder to which the Credential was originally issued,
affirming the authenticity and rightful possession of the Credential.

# Status Assertion Request

The following diagram shows the Wallet Instance requesting a
Status Assertion to a Credential Issuer,
related to a specific Credential issued by the same Credential Issuer.


~~~ ascii-art
+-------------------+                                  +--------------------+
|                   |                                  |                    |
|  Wallet Instance  |                                  | Credential Issuer  |
|                   |                                  |                    |
+--------+----------+                                  +----------+---------+
         |                                                        |
         | HTTP POST /status                                      |
         |  status_assertion_requests = [$StatusAssertionRequest] |
         +-------------------------------------------------------->
         |                                                        |
         |  Status Assertion Responses [...]                      |
         <--------------------------------------------------------+
         |                                                        |
+--------+----------+                                  +----------+---------+
|                   |                                  |                    |
|  Wallet Instance  |                                  | Credential Issuer  |
|                   |                                  |                    |
+-------------------+                                  +--------------------+
~~~

The Wallet Instance sends the Status Assertion request to the
Credential Issuer, where:

- The request MUST contain the base64url encoded hash value of the Digital Credential's
Issuer signed part, such as the Issuer Signed JWT using [@SD-JWT-VC],
or the Mobile Security Object using [@ISO 18013-5],
for which the Status Assertion is requested, and enveloped in a signed
Status Assertion Request object.
- The Status Assertion Request object MUST be signed with the private key corresponding
to the confirmation claim assigned by the Issuer and contained within
the Digital Credential.

The Status Assertion Request object MUST contain the parameters defined in the following table.

| Header | Description | Reference |
| --- | --- | --- |
| **typ** | It MUST be set to `status-assertion-request+jwt` when JWT format is used. It MUST be set to `status-assertion-request+cwt` when CWT format is used. | {{RFC7516}} Section 4.1.1, [RFC9596] |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or any symmetric algorithm (MAC) identifier. | {{RFC7516}} Section 4.1.1 |

| Payload | Description | Reference |
| --- | --- | --- |
| **iss** | Status Assertion Request Issuer identifier. The value is supposed to be used for identifying the Wallet that has issued the request. It is out of scope for this document defining how this value should be set. | {{RFC9126}}, {{RFC7519}} |
| **aud** | It MUST be set with the Credential Issuer Status Assertion endpoint URL as value that identify the intended audience. | {{RFC9126}}, {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. It MUST be superior to the value set for `iat` . | {{RFC9126}}, {{RFC7519}}, {{RFC7515}} |
| **iat** | UNIX Timestamp with the time of JWT/CWT issuance. | {{RFC9126}}, {{RFC7519}} |
| **jti** | Unique identifier for the JWT.  | {{RFC7519}} Section 4.1.7 |
| **cti** | Unique identifier for the CWT.  | {{RFC7519}} Section 4.1.7 |
| **credential_hash** | Hash value of the Digital Credential the Status Assertion is bound to. | this specification |
| **credential_hash_alg** | The Algorithm used of hashing the Digital Credential to which the Status Assertion is bound. The value SHOULD be set to `sha-256`. | this specification |

Below is a non-normative example of a Status Assertion Request with
the JWT headers and payload represented without applying signature and
encoding:

~~~
{
    "alg": "ES256",
    "typ": "status-assertion-request+jwt"
}
.
{
    "iss": "0b434530-e151-4c40-98b7-74c75a5ef760",
    "aud": "https://issuer.example.org/status-assertion-endpoint",
    "iat": 1698744039,
    "exp": 1698830439,
    "jti": "6f204f7e-e453-4dfd-814e-9d155319408c",
    "credential_hash": $hash-about-Issuer-Signed-JWT
    "credential_hash_alg": "sha-256"
}
~~~

Below is a non-normative example of a Status Assertion Request object in CWT format
represented in CBOR diagnostic notation format {{RFC8152}}, where the CWT headers
and payload are presented without applying signature and encoding for better readability:

~~~
   [
       / protected / << {
       / alg / 1: -7 / ES256 /
       / typ / 16: -7 / status-assertion-request+cwt /
     } >>,
     / unprotected / {
     },
     / payload / << {
       / iss    / 1: 0b434530-e151-4c40-98b7-74c75a5ef760 /,
       / aud    / 3: https://issuer.example.org/status-assertion-endpoint /,
       / iat    / 6: 1698744039 /,
       / exp    / 4: 1698830439 /,
       / cti    / 7: 6f204f7e-e453-4dfd-814e-9d155319408c /,
       / credential_hash / 8: $hash-about-MobileSecurityObject /,
       / credential_hash_alg / 9: sha-256 /
     } >>,
   ]
~~~

Below a non-normative example representing a Status Assertion Request array with a
single Status Assertion Request object in JWT format.

~~~
POST /status HTTP/1.1
Host: issuer.example.org
Content-Type: application/json

{
    "status_assertion_requests" : ["${base64url(json({typ: (some pop for status-assertion)+jwt, ...}))}.payload.signature", ... ]
}
~~~

The Status Assertion HTTP request can be sent to a single Credential Issuer
regarding multiple Digital Credentials, and MUST contain a JSON object with
the member `status_assertion_requests`.

The `status_assertion_requests` MUST be set with an array of strings, where
each string within the array represents a Digital Credential
Status Assertion Request object.

The Credential Issuer that receives the Status Assertion Request object
MUST validate that the Wallet Instance making the request is
authorized to request Status Assertions.
Therefore the following requirements MUST be satisfied:

- The Credential Issuer MUST verify the compliance of all elements in the `status_assertion_requests` object
using the confirmation method contained within the Digital Credential where the Status Assertion Request
object is referred to;
- The Credential Issuer MUST verify that it is the legitimate Issuer of the Digital Credential
to which each Status Assertion Request object refers.


# Status Assertion Response

The response MUST include a JSON object with a member
named `status_assertion_responses`, which contains the
Status Assertions and or the Status Assertion Errors
related to the request made by the
Wallet Instance. In the non-normative example below is
represented an HTTP Response with the
`status_assertion_responses` JSON member:

~~~
HTTP/1.1 200 OK
Content-Type: application/json

{
    "status_assertion_responses": ["${base64url(json({typ: status-assertion+jwt, ...}))}.payload.signature", ... ]
}
~~~

The member `status_assertion_responses` MUST be an array of strings,
where each of them represent a Status Assertion Response object,
as defined in
[the section Status Assertion](#status-assertion) or a Status Assertion Error object,
as defined in [the section Status Error](#status-assertion-error).

For each entry in the `status_assertion_responses` array, the following requirements are met:
- Each element in the array MUST match the corresponding element in the request array at
the same position index to which it is related, eg: _[requestAboutA, requestAboutB]_ may produce _[responseAboutA, responseErrorAboutB]_.
- Each element MUST contain the error or the status of the assertion, using the `typ` member
set to "status-assertion+{jwt,cwt}" or "status-assertion-error+{jwt,cwt}", depending by the object type.
- The corresponding entry in the response MUST be of the same data format as requested. For example,
if the entry in the request is "jwt", then the entry at the same position in the response MUST also be "jwt".
- The corresponding entry in the response MUST NOT contain any
information regarding the Verifier to whom it may be presented,
such as the Verifier identifier as the intended audience.

# Status Assertion Error

If the Status Assertion is requested for a non-existent, expired, revoked
or invalid Digital Credential, the
Credential Issuer MUST respond with an HTTP Response with the status
code set to 200 and the `status_assertion_responses` array with the related
Status Assertion Error object.

The Status Assertion Error MUST NOT be presented or provided to a Verifier,
the only audience of the Status Assertion Error is the Holder of the Credential
that has requested the Status Assertion. Therefore,
it is not necessary that the Status Assertion Error
contains the parameter `aud`; if present, it MUST be set to the same
value as the `iss` parameter used by the Wallet in the corresponding
Status Assertion Request object.

Below a non-normative example of a Status Assertion Error object in JWT format,
with the headers and payload represented in JSON and without applying the signature.

~~~
{
    "alg": "ES256",
    "typ": "status-assertion-error+jwt",
    "kid": "Issuer-JWK-KID"
}
.
{
    "iss": "https://issuer.example.org",
    "jti": "6f204f7e-e453-4dfd-814e-9d155319408c"
    "credential_hash": $hash-about-Issuer-Signed-JWT,
    "credential_hash_alg": "sha-256",
    "error": "credential_revoked",
    "error_description": "Credential is revoked."
    }
}
~~~

The Status Assertion Error object MUST contain the parameters described in the
table below:

| Header | Description | Reference |
| --- | --- | --- |
| **typ** | REQUIRED. Depending on the related Status Assertion Request object format, it MUST be set to `status-assertion-error+jwt` or `status-assertion-error+cwt`. | {{RFC7516}} Section 4.1.1 |
| **alg** | REQUIRED. Algorithm used to verify the cryptographic signature of the Status Assertion Error. Status Assertion Error that do not need to be signed SHOULD set the `alg` value to `none`. For further clarification about the requirement of signing the Status Assertion Errors, see Section [Rationale About The Unsigned Status Assertion Errors](#rationale-about-the-unsigned-status-assertion-errors). | {{RFC7516}} Section 4.1.1 |

| Payload | Description | Reference |
| --- | --- | --- |
| **iss** | REQUIRED. It MUST be set to the identifier of the Issuer. | {{RFC9126}}, {{RFC7519}} |
| **jti** | REQUIRED. Unique identifier for the JWT.  | {{RFC7519}} Section 4.1.7 |
| **credential_hash** | REQUIRED. The hash value MUST match the one contained in the Status Assertion Request to which the Status Assertion Error is related. | this specification |
| **credential_hash_alg** |  REQUIRED. The hash algorithm MUST match the one contained in the Status Assertion Request to which the Status Assertion Error is related. | this specification |
| **error** | REQUIRED. The value SHOULD be assigned with one of the error types defined in {{RFC6749}}[Section 5.2](https://tools.ietf.org/html/rfc6749#section-5.2) or defined in the Section [Status Assertion Error Values](status-assertion-error-values). | {{RFC7519}} Section 4.1.7 |
| **error_description** | OPTIONAL. Text that clarifies the nature of the error, such as attribute changes, revocation reasons, in relation to the `error` value.  | {{RFC7519}} Section 4.1.7 |

## Rationale About The Unsigned Status Assertion Errors
To mitigate potential resource exhaustion attacks where an adversary could issue hundreds of fake Status Assertion Requests to force an Issuer to sign numerous Status Assertion Errors, it is advisable to set the header parameter`alg` value to `none` for Status Assertion Errors that do not require signatures. This approach conserves computational resources and prevents abuse, especially in scenarios where the Issuer's implementation could be vulnerable to resource exhaustion attacks. However, even if it is out of the scopes of this specification determine in which the Status Error Assertion signatures are necessary, when the Issuer signs the Status Assertion Errors the Client that received them MUST validate the signature.

## Status Assertion Error Values

The `error` parameter for the Status Assertion Error object MUST be set with one of the values defined in the table below, in addition to the values specified in {{RFC6749}}:

| Error Parameter Value | Description | Reference |
| --- | --- | --- |
| **credential_revoked** | The Digital Credential results as already revoked. The reason of revocation MAY be provided in the `error_description` field. | this specification |
| **credential_updated** | One or more information contained in the Digital Credential are changed. The `error_description` field SHOULD contain a human-readable text describing the general parameters updated without specifying each one. | this specification |
| **credential_invalid** | The Digital Credential is invalid. The `error_description` field SHOULD contain the reason of invalidation. | this specification |
| **invalid_request_signature** | The Status Assertion Request signature validation has failed. This error type is used when the proof of possession of the Digital Credential is found not valid within the Status Assertion Request. | this specification |
| **credential_not_found** | The `credential_hash` value provided in the Status Assertion Request doesn't match with any active Digital Credential. | this specification |
| **unsupported_hash_alg** | The hash algorithm set in `credential_hash_alg` is not supported. | this specification |

# Status Assertion

When a Status Assertion is requested to a Credential Issuer, the
Issuer checks the status of the Digital Credential and creates a
Status Assertion bound to it.

If the Digital Credential is valid, the Credential Issuer
creates a new Status Assertion,
which a non-normative example is given below
where the format is JWT.

~~~
{
    "alg": "ES256",
    "typ": "status-assertion+jwt",
    "kid": $ISSUER-JWKID
}
.
{
    "iss": "https://issuer.example.org",
    "iat": 1504699136,
    "exp": 1504785536,
    "credential_hash": $hash-about-Issuer-Signed-JWT,
    "credential_hash_alg": "sha-256",
    "credential_status_validity": true,
    "cnf": {
        "jwk": {...}
    }
}
~~~

The Status Assertion MUST contain the parameters defined below.

| Header Parameter Name | Description | Reference |
| --- | --- | --- |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or to a symmetric algorithm (MAC) identifier. | {{RFC7515}}, {{RFC7517}} |
| **typ** | It MUST be set to `status-assertion+jwt` when JWT format is used. It MUST be set to `status-assertion+cwt` when CWT format is used. | {{RFC7515}}, {{RFC7517}} and this specification |
| **kid** | Unique identifier of the Credential Issuer JWK. It is required when `x5c` or other cryptographic public key resolution identifiers are not used. | {{RFC7515}} |
| **x5c** | X.509 certificate chain about the Credential Issuer. It is required when `kid` or other parameter are not used. | {{RFC7515}} |

| Payload Parameter Name | Description | Reference |
| --- | --- | --- |
| **iss** | It MUST be set to the identifier of the Issuer. | {{RFC9126}}, {{RFC7519}} |
| **iat** | UNIX Timestamp with the time of the Status Assertion issuance. | {{RFC9126}}, {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. It MUST be greater than the value set for `iat`. | {{RFC9126}}, {{RFC7519}}, {{RFC7515}} |
| **credential_hash** | Hash value of the Digital Credential the Status Assertion is bound to. | this specification |
| **credential_hash_alg** | The Algorithm used of hashing the Digital Credential to which the Status Assertion is bound. The value SHOULD be set to `sha-256`. | this specification |
| **credential_status_validity**| Boolean value determining the absolute validity of the Credential to which the Status Assertion is bound | this specification |
| **cnf** | JSON object containing confirmation methods. The sub-member contained within `cnf` member, such as `jwk` for JWT and `Cose_Key` for CWT, MUST match with the one provided within the related Digital Credential. Other confirmation methods can be utilized when the referenced Digital Credential supports them, in accordance with the relevant standards. | {{RFC7800}} Section 3.1, {{RFC8747}} Section 3.1 |


# Interoperability of Credential Issuers Supporting Status Assertions

This section outlines how Credential Issuers support Status Assertions,
detailing the necessary metadata and practices to integrate into their systems.

## Credential Issuer Metadata

The Credential Issuers that uses the Status Assertions MUST include in their
OpenID4VCI [OpenID4VCI] metadata the claims:

- `status_assertion_endpoint`. REQUIRED. It MUST be an HTTPs URL indicating
the endpoint where the Wallet Instances can request Status Assertions.
- `credential_hash_alg_supported`. REQUIRED. The supported Algorithm used by
the Wallet Instance to hash the Digital Credential for which the
Status Assertion is requested,  using one of the hash algorithms listed
in the [IANA-HASH-REG].


## Issued Digital Credentials

The Credential Issuers that uses the Status Assertions SHOULD include in the
issued Digital Credentials the object `status` with the
JSON member `status_assertion` set to a JSON Object containing the following
member:

- `credential_hash_alg`. REQUIRED. The Algorithm used of hashing the
Digital Credential to which the Status Assertion is bound, using one of the
hash algorithms listed in the [IANA-HASH-REG].
Among the hash algorithms, `sha-256` is recommended and
SHOULD be implemented by all systems.


The non-normative example of an unsecured payload of
an [SD-JWT.VC] is shown below.

~~~
{
 "vct": "https://credentials.example.com/identity_credential",
 "given_name": "John",
 "family_name": "Doe",
 "email": "johndoe@example.com",
 "phone_number": "+1-202-555-0101",
 "address": {
   "street_address": "123 Main St",
   "locality": "Anytown",
   "region": "Anystate",
   "country": "US"
 },
 "birthdate": "1940-01-01",
 "is_over_18": true,
 "is_over_21": true,
 "is_over_65": true,
 "status": {
    "status_assertion": {
        "credential_hash_alg": "sha-256",
    }
 }
}
~~~

### Credential Issuer Implementation Considerations

When the Digital Credential is issued, the Credential Issuer should
calculate the hash value using the algorithm specified in
`status.status_assertion.credential_hash_alg` and store this information
in its database. This practice enhances efficiency by allowing the
Credential Issuer to quickly compare the requested
`credential_hash` with the pre-calculated one, when processing
Status Assertion requests made by Holders.

# Presenting Status Assertions

The Wallet Instance that provides the Status Assertions using [OpenID4VP], SHOULD include in the
`vp_token` JSON array, as defined in [OpenID4VP], the Status Assertion along with the
related Digital Credential.

The Verifier that receives a Digital Credential supporting the Status Assertion,
SHOULD:

- Decode and validate the Digital Credential;
- Check the presence of `status.status_assertion` in the
Digital Credential. If true, the Verifier SHOULD:
  - produce the hash of the Digital Credential using the
  hashing algorithm configured in `status.status_assertion.credential_hash_alg`;
  - decode all the Status Assertions provided in the presentation,
  by matching the JWS Header parameter `typ` set to `status-assertion+jwt`
  and looking for the `credential_hash` value that matches with the
  hash produced at the previous point;
  - evaluate the validity of the Status Assertion.

# Considerations On Revocation Verification

The recommendation for Verifiers to check the revocation status
of Digital Credentials as a 'SHOULD' instead of a 'MUST' acknowledges
that the decision to verify revocation is not absolute and may be
influenced by various factors. Consider as an example the case of age-over x;
even if it has expired, it may still perform its intended purpose.
As a result, the expiration status alone does not render it invalid.
The adaptability recognizes that the need to verify revocation status
may not always coincide with the actual usability of a Digital Credential,
allowing Verifiers to examine and make educated conclusions based on a
variety of scenarios.

# Detailed Status Assertions

Status Assertions can introduce a more accurate level of detail, and therefore not necessarly limited to simple boolean information.
This enables Verifier policies to be conditioned on the presence of secured information, instead of the absence of information.
This section proposes syntax to support detailed assertions.
The `credential_status_validity` claim MUST be present and be either `true` or `false`.
The `credential_status` claim MAY be present and if present MUST be an object.
The semantics of the claims within the `credential_status` object are determined by the Credential Issuer.

An example of a boolean status is:

~~~
{
    "alg": "ES256",
    "typ": "status-assertion+jwt",
    "kid": "w8ZOZRcx21Zpry7H-0VLBsH7Wf7WXb6TeK3qVMCpY44"
}
.
{
    "iss": "https://issuer.example.org",
    "iat": 1504699136,
    "exp": 1504785536,
    "credential_hash": "xnlAq6Ma8fgu1z4hdGphJnKLulaVHpLCFeZFUGpQ2dA",
    "credential_hash_alg": "sha-256",
    "credential_status_validity": false,
    "credential_status": {
      "revoked": false,
      "suspended": true,
    },
    "cnf": {
      "jwk": {
        "alg": "ES256",
        "kty": "EC",
        "crv": "P-256",
        "x": "_2ySUmWFjwmraNlo15r6dIBXerVdy_NpJuwAKJMFdoc",
        "y": "MV3C88MhhEMba6oyMBWuGeB3dKHP4YADJmGyJwwILsk"
      }
    }
}
~~~

An example of an enumeration status is:

~~~
{
    "alg": "ES256",
    "typ": "status-assertion+jwt",
    "kid": "w8ZOZRcx21Zpry7H-0VLBsH7Wf7WXb6TeK3qVMCpY44"
}
.
{
    "iss": "https://issuer.example.org",
    "iat": 1504699136,
    "exp": 1504785536,
    "credential_hash": "xnlAq6Ma8fgu1z4hdGphJnKLulaVHpLCFeZFUGpQ2dA",
    "credential_hash_alg": "sha-256",
    "credential_status_validity": false,
    "credential_status": {
      "state": "suspended", // or "revoked"
    },
    "cnf": {
      "jwk": {
        "alg": "ES256",
        "kty": "EC",
        "crv": "P-256",
        "x": "_2ySUmWFjwmraNlo15r6dIBXerVdy_NpJuwAKJMFdoc",
        "y": "MV3C88MhhEMba6oyMBWuGeB3dKHP4YADJmGyJwwILsk"
      }
    }
}
~~~

An example of dynamic status using a small matrix:

~~~
{
    "alg": "ES256",
    "typ": "status-assertion+jwt",
    "kid": "w8ZOZRcx21Zpry7H-0VLBsH7Wf7WXb6TeK3qVMCpY44"
}
.
{
    "iss": "https://issuer.example.org",
    "iat": 1504699136,
    "exp": 1504785536,
    "credential_hash": "xnlAq6Ma8fgu1z4hdGphJnKLulaVHpLCFeZFUGpQ2dA",
    "credential_hash_alg": "sha-256",
    "credential_status_validity": true,
    "credential_status": {
      "preferences": [[1, 0.25, 0.76 ...] ...]
    },
    "cnf": {
      "jwk": {
        "alg": "ES256",
        "kty": "EC",
        "crv": "P-256",
        "x": "_2ySUmWFjwmraNlo15r6dIBXerVdy_NpJuwAKJMFdoc",
        "y": "MV3C88MhhEMba6oyMBWuGeB3dKHP4YADJmGyJwwILsk"
      }
    }
}
~~~

An example of multiple assertions:

~~~
HTTP/1.1 200 Created
Content-Type: application/json

{
    "status_assertion_responses": [
      $JWT_1, // Not revoked, boolean assertion
      $JWT_2, // alg = none, suspended indicator
      $JWT_3, // Preferences matrix assertion
    ]
}
~~~

# Security Considerations

TODO Security

# Privacy Considerations

In the design and implementation of Status Assertions, particular
attention has been paid to privacy considerations to ensure that the
system is respectful of user privacy and compliant with relevant
regulations.

## Privacy Consideration: Status Assertion Request Opacity

The request for a Status Assertion does not transmit the Digital Credential
for which the status is being attested. Instead, it includes a proof of
possession (PoP) of the Digital Credential that is only interpretable by the
Credential Issuer who issued the Digital Credential for which the
Status Assertion is requested. This PoP can be achieved through a
cryptographic signature using the public key contained within the
Digital Credential over the request. This method is essential for
preventing the potential for fraudulent requests intended to mislead or
disclose sensitive information to unintended parties. By separating the
Digital Credential from the Status Assertion Request, the system ensures
that the request does not inadvertently disclose any information about
the Digital Credential or its Holder. This strategy significantly
enhances the privacy and security of the system by preventing the
assertion process from being used to collect information about
Digital Credentials or their Holders through deceptive requests.

## Privacy Consideration: Opacity of Status Assertion Content

An important privacy consideration is how the Status Assertion is
structured to ensure it does not reveal any information about the User or
the Holder of the Digital Credential. The Status Assertion is crafted
to prove only the vital information needed to verify the current state
of a Digital Credential, moving beyond simple revocation or
suspension checks. This is done by focusing the assertion content on the
Digital Credential's present condition and the method for its
verification, rather than on the identity of the Digital Credential's
Holder. This approach is key in keeping the User's anonymity intact,
making sure that the Status Assertion can be applied in various
verification situations without risking the privacy of the people involved.

## Unlinkability and Reusability of Status Assertions

Status Assertions are designed to uphold privacy by allowing Verifiers
to operate independently, without the need for interaction or information
disclosure to third-party entities or other Verifiers. This design is
pivotal in ensuring unlinkability between Verifiers, where actions
taken by one Verifier cannot be correlated or linked to actions
taken by another. Verifiers can directly validate the status of a
Digital Credential through the Status Assertion, eliminating the need
for external communication. This mechanism is key in protecting the
privacy of individuals whose Digital Credentials are being verified, as
it significantly reduces the risk of tracking or profiling based on
verification activities across various services.

While Status Assertions facilitate unlinkability, they are not inherently
"single use." The specification accommodates the batch issuance of multiple
Status Assertions, which can be single-use. However, particularly for
offline interactions, a Single Assertion may be utilized by numerous
Verifiers. This flexibility ensures that Status Assertions can support
a wide range of verification scenarios, from one-time validations to
repeated checks by different entities, without compromising the privacy
or security of the Digital Credential Holder.

## Untrackability by Digital Credential Issuers and the "Phone Home" Problem

A fundamental aspect of the privacy-preserving attributes of
Status Assertions is their ability to address the "phone home" problem,
which is the prevention of tracking by Digital Credential Issuers.
Traditional models often require Verifiers to query a central status
list or contact the issuer directly, a process that can inadvertently
allow Credential Issuers to track when and where a Digital Credential
is verified. Status Assertions, however, encapsulate all necessary
verification information within the assertion itself. This design choice
ensures that Credential Issuers are unable to monitor the verification
activities of their issued Digital Credentials, thereby significantly
enhancing the privacy of the Holder. By removing the need for real-time
communication with the Issuer for status checks, Status Assertions
effectively prevent the Issuer from tracking verification activities,
further reinforcing the system's dedication to protecting User privacy.

## Minimization of Data Exposure

The Status Assertions are designed around the data minimization principle.
Data minimization ensures that only the necessary information required
for the scope of attesting the non revocation status of the Digital
Credential. This minimizes the exposure of potentially sensitive data.

## Resistance to Enumeration Attacks

The design of Status Assertions incorporates measures to resist
enumeration attacks, where an adversary attempts to gather information
by systematically verifying different combinations of data.
By implementing robust cryptographic techniques and limiting the
information contained in Status Assertions, the system reduces the
feasibility of such attacks. This consideration is vital for safeguarding
the privacy of the Holders and for ensuring the integrity of
the verification process.

Status Assertions are based on a privacy-by-design approach, reflecting
a deliberate effort to balance security and privacy needs in the
Digital Credential ecosystem.

## Validity Reasons

Status Assertions may disclose details about the Holder or subject that were not initially committed to during the original Credential issuance. This can potentially expose additional information that was not part of the original credentialing process.
Providing a reason that a Digital Credential is no longer valid can be essential to certain use cases, and unacceptable for others
For example, in a healthcare setting, a patient should not have medical reasons for a suspended credential disclosed in assertions of suspension.
However, in a supply chain context, a product suspension might benefit from additional information, such as batch or lot information.

# IANA Considerations

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry [IANA.JWT] established by {{RFC7519}}.


*  Claim Name: `credential_hash`
*  Claim Description: Hash value of the Digital Credential the Status Assertion is bound to.
*  Change Controller: IETF
*  Specification Document(s): [this specification](#status-assertion)

<br/>

*  Claim Name: `credential_hash_alg`
*  Claim Description: The Algorithm used of hashing the Digital Credential to which the Status Assertion is bound.
*  Change Controller: IETF
*  Specification Document(s): [this specification](#status-assertion)

## Media Type Registration

This section requests registration of the following media types [RFC2046] in
the "Media Types" registry [IANA.MediaTypes] in the manner described
in [RFC6838].

To indicate that the content is a JWT-based Status Assertion:

  * Type name: application
  * Subtype name: status-assertion-request+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary; A JWT-based Status Assertion Request object is a JWT; JWT values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') characters.
  * Security considerations: See (#Security) of [this specification](#security-considerations)
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for requesting Status Assertions.
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is a CWT-based Status Assertion Request:

  * Type name: application
  * Subtype name: status-assertion-request+cwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [this specification](#security-considerations)
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for requesting Status Assertions.
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is a JWT-based Status Assertion:

  * Type name: application
  * Subtype name: status-assertion+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [this specification](#security-considerations)
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for issuing or presenting Status Assertions.
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is a CWT-based Status Assertion:

  * Type name: application
  * Subtype name: status-assertion+cwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [this specification](#security-considerations)
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for issuing or presenting Status Assertions.
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is a JWT-based Status Assertion Error:

  * Type name: application
  * Subtype name: status-assertion-error+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [this specification](#security-considerations)
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for issuing Status Assertions Request Errors.
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is a CWT-based Status Assertion Error:

  * Type name: application
  * Subtype name: status-assertion-error+cwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [this specification](#security-considerations)
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for issuing Status Assertions Request Errors.
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Giuseppe De Marco, gi.demarco@innovazione.gov.it
  * Change controller: IETF
  * Provisional registration? No

--- back

# Acknowledgments

We would like to thank:

- Paul Bastien
- Sara Casanova
- Emanuele De Cupis
- Riccardo Iaconelli
- Marina Adomeit
- Victor Näslund
- Giada Sciarretta
- Amir Sharif


# Document History

-02

* Removed several comparisons with OAuth Status List
* Status Assertion Request and Response is now a json array with multiple entries.
* Better generalization about the confirmation methods.
* Removed any informative comparison with OAuth Status List.
* JWT and CWT typ.
* Name of the draft changed from `OAuth Status Attestations` to `OAuth Status Assertions`.
* Extended Status Assertion errors table added in [the section Status Error](#status-assertion-error).
