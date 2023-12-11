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
  RFC7519: RFC7519
  RFC8392: RFC8392

informative:


--- abstract

Status Attestations act as evidence that a specific credential or token, whether in JSON Web Tokens (JWT) {{RFC7519}} or CBOR Web Tokens (CWT) format {{RFC8392}}, has not been revoked and remains valid. These attestations are designed to be short-lived and statically provided to verifiers, eliminating the need for verifiers to obtain additional information from third-party systems about a token or a digital credential.


--- middle

# Introduction

Status Attestations play a crucial role in maintaining the integrity and trustworthiness of token and digital credentials.
Status Attestations serve as proof that a particular digital credential or token, whether in JSON Web Tokens (JWT) or CBOR Web Tokens (CWT) format, has not been revoked and is still valid.

In many scenarios, a digital credential may be presented to a verifier long after it has been issued. During this interval, the credential could potentially be invalidated for various reasons. To ensure the credential's validity, the issuer provides a short-lived Status Attestation to the credential's Holder. This attestation is bound to the credential and can be presented to a verifier, along with the credential itself, as proof of the credential's non-revocation status.

Status Attestations are designed to be privacy-preserving and secure. These attestations are essential for enabling offline use cases and ensuring the security of the digital credential system. They provide a balance between scalability, security, and privacy by minimizing the status information.


~~~ ascii-art
+---------------------+                             +-------------------+
|                     | Requests Status Attestation |                   |
|                     |---------------------------->|                   |
|   Wallet Instance   |                             | Credential Issuer |
| (Holds credentials) |                             |    (JWT or CWT)   |
|                     | Status Attestation          |                   |
|                     |<----------------------------|                   |
+---------------------+                             +-------------------+


+---------------------+                             +----------+
|                     | Presents credentials and    |          |
|   Wallet Instance   | Status Attestation          | Verifier |
|                     |---------------------------->|          |
+---------------------+                             +----------+
~~~


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Issuer:
: An entity that ...

Relying Party:
: An entity that.... Also known as Verifier.

Wallet Instance:
: An entity that.... Also known as Wallet.

Attestation Owner:
: An entity that.... Also known as Wallet.

# Rationale

Status Lists [@!I-D.looker-oauth-jwt-cwt-status-list] are suitable for specific scenarios, especially when the Verifier needs to verify the status of a credential at a later time after the User has presented the digital credential. However, there are instances where the Verifier only needs to check the revocation status of a digital credential at the time of presentation, or situations where the Verifier should not be able to check the status of a credential over time due to privacy considerations.

In scenarios where the Verifier, Credential Issuer, and Status List Provider are all part of the same domain or operate within a context where a high level of trust exists between them and the End-User, the OAuth Status List is the optimal solution, provided that the following privacy risks are either mitigated or not present:

- A Status List provider might be aware of the association between a specific list and a Credential Issuer, especially if the latter only issues a single type of Credential. This could inadvertently reveal to the Status List provider which list corresponds to which Credential.
- A Verifier retrieves a Status List by establishing a TCP/IP connection with a Status List provider. This allows the Status List provider to obtain the IP address of the Verifier and potentially link it to a specific Credential type and Issuer associated with that Status List. A malicious Status List provider could exploit internet diagnostic tools, such as Whois or GeoIP lookup, to gather additional information about the requestor. This could inadvertently disclose to the Status List provider which Credential the requestor is using and from which Credential Issuer, information that in some cases should remain confidential.

However, Status Attestations differ significantly from Status Lists in several ways:

1. **Privacy**: Status Attestations are designed to be privacy-preserving. They do not require the Verifier to gather any additional information from third-party systems, thus preventing potential privacy leaks.

2. **Static Verification**: Status Attestations are designed to be statically provided to Verifiers by Wallet Instance (Attestation Owner). This means that once an Attestation is issued, it can be verified without any further communication with the Issuer or any other party.

3. **Token Formats**: Status Attestations are suitable for both JSON Web Tokens (JWT) and CBOR Web Tokens (CWT), making them versatile for different use cases.

4. **Trust Model**: Status Attestations operate under a model where the Verifier trusts the Issuer to provide accurate status information. In contrast, Status Lists operate under a model where the Verifier trusts the Status List Provider to maintain an accurate and up-to-date list of token statuses.

5. **Offline flow**: A Status List can be accessed by a Verifier when an internet connection is present, otherwise a Status List Token can be included within a Digital Credential, necessitating the Wallet Instance to acquire a new Digital Credential for a specific presentation. Differently, the Status Attestations enable the User to persistently use their Digital Credential, as long as the linked Status Attestation is provisioned, presented, and has not expired.

# Requirements

The Status Attestation:

- MUST be presented in conjunction with the digital Credential. The Status Attestation MUST be timestamped with its issuance datetime, always referring to a previous period.
- MUST contain the expiration datetime after which the digital Credential MUST NOT be considered valid anymore.
- enables offline use cases as it MUST be statically validated using the cryptographic signature of the Issuer.


Status Attestation Request
--------------------------

The Issuer provides the Wallet Instance with a Status Attestation, bound to a Credential so that the Wallet Instance can present it to a Verifier, along with the Credential itself, as a proof of non-revocation status of the Credential.

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
         |  credential_proof=$CredentialPoPJWT           |
         |  client_assertion_type                        |
         |  client_assertion=WIA~POP                     |
         +----------------------------------------------->
         |                                               |
         |  Response with Status Attestation JWT |
         <-----------------------------------------------+
         |                                               |
+--------+----------+                         +----------+---------+
|                   |                         |                    |
|  Wallet Instance  |                         | Credential Issuer  |
|                   |                         |                    |
+-------------------+                         +--------------------+

~~~

**Step 1 (Status Attestation Request)**: The Wallet Instance sends the Status Attestation Request to the Issuer. The request MUST contain the Wallet Instance Attestation with its Proof of Possession and a Credential Proof of Possession JWT, signed  with the private key related to the public key contained within the Credential.

~~~
POST /status HTTP/1.1
Host: issuer.example.org
Content-Type: application/x-www-form-urlencoded

credential_proof=$CredentialPoPJWT
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation
&client_assertion=$WIA~WIA-PoP
~~~

The Issuer verifies the signature of the PoP JWTs using the public key contained in the `client_assertion` and the Credential, which is the proof that the Wallet Instance owns the private keys associated with the Wallet Instance Attestation and Credential. Therefore the Wallet Instance is entitled to request its Status Attestation.

Status Attestation
-------------------

The Issuer checks the status of the Credential and creates a Status Attestation bound to it.
The Issuer creates a new Status Attestation, a non-normative example of which is given below.

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

Status Attestation Response
---------------------------

The Issuer then returns the Status Attestation to the Wallet Instance, as in the following non-normative example.

~~~

    HTTP/1.1 201 OK
    Content-Type: application/json

    {
        "non_revocation_attestation": "eyJhbGciOiJFUzI1NiIsInR5cCI6IndhbGxldC1...",
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
