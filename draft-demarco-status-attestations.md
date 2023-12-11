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

Status Attestations play a vital role in affirming the validity of digital credentials or tokens, supporting privacy preservation and offline use cases. Status Attestations act as evidence that a specific credential or token, whether in JSON Web Tokens (JWT) {{RFC7519}} or CBOR Web Tokens (CWT) format {{RFC8392}}, has not been revoked and remains valid. These attestations are designed to be short-lived and statically provided to verifiers, eliminating the need for verifiers to obtain additional information from third-party systems.


--- middle

# Introduction

Status Attestations play a crucial role in maintaining the integrity and trustworthiness of token and digital credentials.
Status Attestations serve as proof that a particular digital credential or token, whether in JSON Web Tokens (JWT) or CBOR Web Tokens (CWT) format, has not been revoked and is still valid.

In many scenarios, a digital credential may be presented to a verifier long after it has been issued. During this interval, the credential could potentially be invalidated for various reasons. To ensure the credential's validity, the issuer provides a short-lived Status Attestation to the credential's Holder. This attestation is bound to the credential and can be presented to a verifier, along with the credential itself, as proof of the credential's non-revocation status.

Status Attestations are designed to be privacy-preserving and secure. These attestations are essential for enabling offline use cases and ensuring the security of the digital credential system. They provide a balance between scalability, security, and privacy by minimizing the status information.


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

Status Lists [@!I-D.looker-oauth-jwt-cwt-status-list] indeed exist and are quite effective for certain use cases, particularly when the Verifier, Credential Issuer, and Status List Provider all belong to the same domain or operate within a context where a high level of trust exists between them and the End-User, mitigating any privacy concerns, like the ones listed below:

- A Status List provider may know which list is linked to which Credential Issuer and this latter may only issue a single Credential type, exposing the evidence to the Status List provider of which list is related to which credential;
- A Verifier, or Relying Party, queries a Status List using a TCP/IP connection with a Status List provider. The Status List provider then may have the IP address of the requestor and both the Credential type and the Credential Issuer linked to that specific Status List. A malicious Status List provider may use internet diagnostic tools, such as the Whois and/or the GeoIP lookup, to gather informations about the requestor. This exposes to the Status List provider information about which Credential the requestor is consuming from which Credential Issuer, while this information, in some cases, must not be provided.

However, Status Attestations differ significantly from Status Lists in several ways:

1. **Privacy**: Status Attestations are designed to be privacy-preserving. They do not require the Verifier to gather any additional information from third-party systems, thus preventing potential privacy leaks.

2. **Static Verification**: Status Attestations are designed to be statically provided to Verifiers by Wallet Instance (Attestation Owner). This means that once an Attestation is issued, it can be verified without any further communication with the Issuer or any other party. In contrast, Status Lists may require dynamic checks or updates, which could involve additional communication with the Status List Provider.

3. **Token Formats**: Status Attestations are suitable for both JSON Web Tokens (JWT) and CBOR Web Tokens (CWT), making them versatile for different use cases. Status Lists, however, may not support all token formats.

4. **Trust Model**: Status Attestations operate under a model where the Verifier trusts the Issuer to provide accurate status information. In contrast, Status Lists operate under a model where the Verifier trusts the Status List Provider to maintain an accurate and up-to-date list of token statuses.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
