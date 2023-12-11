---
title: "OAuth Status Attestations"
abbrev: "OAuth Status Attestations"
category: info

docname: draft-demarco-status-attestations-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
keyword:
 - digital credentials
 - status list
 - revocation
venue:
  github: "peppelinux/draft-demarco-status-attestations"
  latest: "https://peppelinux.github.io/draft-demarco-status-attestations/draft-demarco-status-attestations.html"

author:
 -
    fullname: Giuseppe De Marco
    organization: Dipartimento per la trasformazione digitale
    email: gi.demarco@innovazione.gov.it
 -
    fullname: Francesco Marino
    organization: Istituto Poligrafico e Zecca dello Stato
    email: fa.marino@ipzs.it

normative:
  RFC7515: RFC7515
  RFC7516: RFC7516
  RFC7517: RFC7517
  RFC7519: RFC7519
  RFC7638: RFC7638
  RFC7800: RFC7800
  RFC8392: RFC8392
  RFC9126: RFC9126

informative:


--- abstract

Status Attestations are verifiable proofs about the validity status of a  digital credential or token,
in the form of JSON Web Tokens (JWT) [RFC7519] or CBOR Web Tokens (CWT) format [RFC8392].
Status Attestations are designed to be short-lived,
periodically supplied to their holders who then present them to verifiers.
This approach eliminates the need for verifiers to seek additional information
about a token or digital credential from third-party systems.


--- middle

# Introduction

Status Attestations play a crucial role in maintaining the integrity and
trustworthiness of token and digital credentials.
Status Attestations serve as proof that a particular digital credential or token,
whether in JSON Web Tokens (JWT) or CBOR Web Tokens (CWT) format,
has not been revoked and is still valid.

In many scenarios, a digital credential may be presented to a verifier long after it has been issued.
During this interval, the credential could potentially be invalidated for various reasons.
To ensure the credential's validity, the issuer provides a short-lived Status Attestation to the credential's Holder.
This attestation is bound to the credential and can be presented to a verifier,
along with the credential itself, as proof of the credential's non-revocation status.

Status Attestations are designed to be privacy-preserving and secure.
These attestations are essential for enabling offline use cases and ensuring the
security of the digital credential system.
They provide a balance between scalability, security, and
privacy by minimizing the status information.


~~~ ascii-art
+-----------------+                             +-------------------+
|                 | Requests Status Attestation |                   |
|                 |---------------------------->|                   |
| Wallet Instance |                             | Credential Issuer |
|                 | Status Attestation          |                   |
|                 |<----------------------------|                   |
+-----------------+                             +-------------------+


+-- ----------------+                             +----------+
|                   | Presents credential and     |          |
|  Wallet Instance  | Status Attestation          | Verifier |
|                   |---------------------------->|          |
+-------------------+                             +----------+
~~~


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Terminology

Issuer:
: Entity that is responsible for the issuance of the Digital Credentials.
This includes the lifecycle of the Credentials, their issuance, and their validity status.

Relying Party:
: Entity that relies on the validity of the digital credentials presented to it. This entity, also known as a Verifier, needs to verify the authenticity and validity of the Credentials, including their revocation status, before accepting them.

Wallet Instance:
: Entity that represents the digital Wallet of a User. Also known as Wallet or Holder, it is responsible for storing and managing the User's digital credentials. It can present Credentials to Verifiers and request Status Attestations from Issuers.

Attestation Owner:
: Entity that owns an attestation, typically the Holder of the Digital Credential. Also known as Wallet or Holder, it is responsible for presenting the attestation, along with the Digital Credential, to the Verifier.


# Rationale

OAuth Status Lists [@!I-D.looker-oauth-jwt-cwt-status-list] are suitable for specific scenarios, especially when the Verifier needs to verify the status of a Credential at a later time after the User has presented the Digital Credential. However, there are instances where the Verifier only needs to check the revocation status of a Digital Credential at the time of presentation, or situations where the Verifier should not be able to check the status of a credential over time due to privacy requirements.

In scenarios where the Verifier, Credential Issuer, and Status List Provider are all part of the same domain or operate within a context where a high level of trust exists between them and the End-User, the OAuth Status List is the optimal solution. Other cases may expose the following privacy risks when using OAuth Status List [@!I-D.looker-oauth-jwt-cwt-status-list]:

- A Status List provider might be aware of the association between a specific list and a Credential Issuer, especially if the latter only issues a single type of Credential. This could inadvertently reveal to the Status List provider which list corresponds to which Credential.
- A Verifier retrieves a Status List by establishing a TCP/IP connection with a Status List provider. This allows the Status List provider to obtain the IP address of the Verifier and potentially link it to a specific Credential type and Issuer associated with that Status List. A malicious Status List provider could exploit internet diagnostic tools, such as Whois or GeoIP lookup, to gather additional information about the requestor. This could inadvertently disclose to the Status List provider which Credential the requestor is using and from which Credential Issuer, information that in some cases should remain confidential.

However, Status Attestations differ significantly from Status Lists in several ways:

1. **Privacy**: Status Attestations are designed to be privacy-preserving. They do not require the Verifier to gather any additional information from third-party systems, thus preventing potential privacy leaks.

2. **Static Verification**: Status Attestations are designed to be statically provided to Verifiers by Wallet Instance (Attestation Owner). This means that once an Attestation is issued, it can be verified without any further communication with the Issuer or any other party.

3. **Token Formats**: Status Attestations are suitable for both JSON Web Tokens (JWT) and CBOR Web Tokens (CWT), making them versatile for different use cases.

4. **Trust Model**: Status Attestations operate under a model where the Verifier trusts the Issuer to provide accurate status information. In contrast, Status Lists operate under a model where the Verifier trusts the Status List Provider to maintain an accurate and up-to-date list of token statuses.

5. **Offline flow**: A Status List can be accessed by a Verifier when an internet connection is present. Differently OAuth Status List defines how to provide a static Status List Token, to be included within a Digital Credential. This requires the Wallet Instance to acquire a new Digital Credential for a specific presentation. Even if similar to the Status List Token, the Status Attestations enable the User to persistently use their preexistent Digital Credentials, as long as the linked Status Attestation is provisioned, presented to the Verifier, and not expired.


# Requirements

The Status Attestation:

- MUST be presented in conjunction with the Digital Credential. The Status Attestation MUST be timestamped with its issuance datetime, always referring to a previous period.
- MUST contain the expiration datetime after which the Digital Credential MUST NOT be considered valid anymore.
- enables offline use cases as it MUST be statically validated using the cryptographic signature of the Issuer.

Note that in this specification the examples and the normative properties
of attestations are reported in accordance with the JWT standard, while
for the purposes of this specification, any credential or attestation
format format may be used, as long as all attributes and requirements
of the attributes are satisfied.


# Status Attestation Request

The Issuer provides the Wallet Instance with a Status Attestation, bound
to a Credential so that the Wallet Instance can present it to a Verifier,
along with the Credential itself, as a proof of non-revocation status of the Credential.

The following diagram shows the Wallet Instance requesting a Status Attestation
related to a specific Credential, to the Issuer.


~~~ ascii-art
+-------------------+                         +--------------------+
|                   |                         |                    |
|  Wallet Instance  |                         | Credential Issuer  |
|                   |                         |                    |
+--------+----------+                         +----------+---------+
         |                                               |
         | HTTP POST /status                             |
         |  credential_pop = $CredentialPoPJWT           |
         +----------------------------------------------->
         |                                               |
         |  Response with Status Attestation JWT         |
         <-----------------------------------------------+
         |                                               |
+--------+----------+                         +----------+---------+
|                   |                         |                    |
|  Wallet Instance  |                         | Credential Issuer  |
|                   |                         |                    |
+-------------------+                         +--------------------+
~~~

The Wallet Instance sends the Status Attestation Request to the Issuer.
The request MUST contain the Credential which is intended to obtain the Status Attestation
and a Proof of Possession of it, signed  with the private key related to the public key contained within the Credential.

~~~
POST /status HTTP/1.1
Host: issuer.example.org
Content-Type: application/x-www-form-urlencoded

credential_pop=$CredentialPoPJWT
~~~

The Issuer verifies the signature of the PoP using the public key contained in the `client_assertion` and the Credential, which is the proof that the Wallet Instance owns the private keys associated with the Digital Credential. Therefore the Wallet Instance is entitled to request its Status Attestation.


## Digital Credential Proof of Possession

The Wallet that holds a Digital Credential, when requests a Status Attestation,
MUST give the proof of possession of the Credential to the Credential Issuer.

Below a non-normative example of a Credential PoP is given by the following JWT headers and payload:

~~~
{
    "alg": "ES256",
    "typ": "revocation-request+jwt",
    "kid": $WIA-CNF-JWKID

}
.
{
    "iss": "0b434530-e151-4c40-98b7-74c75a5ef760",
    "aud": "https://issuer.example.org",
    "iat": 1698744039,
    "exp": 1698744139,
    "jti": "6f204f7e-e453-4dfd-814e-9d155319408c",
    "format": "vc+sd-jwt",
    "credential": $Issuer-Signed-JWT
}
~~~

The Credential Proof of Possession MUST be a JWT that MUST contain the parameters (JOSE Header and claims) in the following table.

| JOSE header | Description | Reference |
| --- | --- | --- |
| **typ** | It MUST be set to revocation-request+jwt | {{RFC7516}} Section 4.1.1 |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or any symmetric algorithm (MAC) identifier. | {{RFC7516}} Section 4.1.1 |
| **kid** | Unique identifier of the jwk, as used for the key binding of the Credential. he JWT MUST be signed with the private key whihc the public key is contained in the Credential. |  |

| Claim | Description | Reference |
| --- | --- | --- |
| **iss** | Wallet identifier. | {{RFC9126}} and {{RFC7519}} |
| **aud** | It MUST be set to the identifier of the Credential Issuer. | {{RFC9126}} and {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. | {{RFC9126}} and {{RFC7519}} |
| **iat** | UNIX Timestamp with the time of JWT issuance. | {{RFC9126}} and {{RFC7519}} |
| **jti** | Unique identifier for the JWT.  | {{RFC7519}} Section 4.1.7 |
| **format** | The data format of the Credential. Eg: `vc+sd-jwt` for SD-JWT, `vc+mdoc` for ISO/IEC 18013-5 MDOC CBOR | |
| **credential** | It MUST contain the Credential according to the data format given in the `format` claim. | |


# Status Attestation

The Issuer checks the status of the Credential and creates a Status Attestation bound to it.
The Issuer creates a new Status Attestation, which a non-normative example is given below.

~~~
{
    "alg": "ES256",
    "typ": "non-revocation-attestation+jwt",
    "kid": $ISSUER-JWKID
}
.
{
    "iss": "https://issuer.example.org",
    "iat": 1504699136,
    "exp": 1504700136,
    "credential_hash": $CREDENTIAL-HASH,
    "credential_hash_alg": "sha-256",
    "cnf": {
        "jwk": {...}
    }
}
~~~

The Status Attestation MUST contain the following claims when the JWT format is used.

| JOSE Header | Description | Reference |
| --- | --- | --- |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or to a symmetric algorithm (MAC) identifier. | {{RFC7515}}, {{RFC7517}} |
| **typ** | It MUST be set to `status-attestation+jwt`. | {{RFC7515}}, {{RFC7517}}, this specification |
| **kid** | Unique identifier of the Issuer jwk. | {{RFC7638}} Section 3 |

| Claim | Description | Reference |
| --- | --- | --- |
| **iss** | It MUST be set to the identifier of the Issuer. | {{RFC9126}} and {{RFC7519}} |
| **iat** | UNIX Timestamp with the time of there Status Attestation issuance. | {{RFC9126}} and {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiry time of the Status Attestation. | {{RFC9126}} and {{RFC7519}} |
| **credential_hash** | Hash value of the Credential the Status Attestation is bound to. | This specification |
| **credential_hash_alg** | The Algorithm used of hashing the Credential to which the Status Attestation is bound. The value SHOULD be set to `S256`. | This specification |
| **cnf** | JSON object containing the cryptographic key binding. The cnf jwk value MUST match with the one provided within the related Credential. | {{RFC7800}} Section 3.1 |


# Status Attestation Response

The Issuer then returns the Status Attestation to the Wallet Instance, as in the following non-normative example.

~~~
HTTP/1.1 201 OK
Content-Type: application/json

{
    "non_revocation_attestation": "eyJhbGciOiJFUzI1Ni ...",
}
~~~


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back


# Acknowledgments
{:numbered="false"}

TODO acknowledge.
