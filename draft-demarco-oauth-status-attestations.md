---
title: "OAuth Status Attestations"
abbrev: "OAuth Status Attestations"
category: info

docname: draft-demarco-oauth-status-attestations-latest
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
    fullname: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
 -
    fullname: Francesco Marino
    organization: Istituto Poligrafico e Zecca dello Stato
    email: fa.marino@ipzs.it

normative:
  RFC7515: RFC7515
  RFC7516: RFC7516
  RFC7517: RFC7517
  RFC7519: RFC7519
  RFC7800: RFC7800
  RFC9126: RFC9126

informative:


--- abstract

Status Attestation is a signed object that demonstrates the validity status of a
digital credential.
These attestations are periodically provided
to holders, who can present these to verifiers along
with the corresponding digital credentials.
The approach outlined in this document
makes the verifier able to check the non-revocation of a digital credential
without requiring to query any third-party entities.

--- middle

# Introduction

Status Attestations ensure the integrity and trustworthiness of digital credentials, whether in JSON Web Tokens (JWT) or CBOR Web Tokens (CWT) format, certifying their validity and non-revocation status. They function similarly to OCSP Stapling, allowing wallet instances to present time-stamped attestations from the Credential Issuer.
The approach defined in this specification allows the verification of credentials against any revocation, without direct queries to the issuer, enhancing privacy, reducing latency, and enabling offline verification.


~~~ ascii-art
+-----------------+                             +-------------------+
|                 | Requests Status Attestation |                   |
|                 |---------------------------->|                   |
| Wallet Instance |                             | Credential Issuer |
|                 | Status Attestation          |                   |
|                 |<----------------------------|                   |
+-----------------+                             +-------------------+
~~~
Figure 1: Status Attestation Issuance Flow

This figure illustrates the process by which a Wallet Instance requests a Status Attestation from the Credential Issuer and subsequently receives it.


~~~ ascii-art
+-- ----------------+                             +----------+
|                   | Presents Digital Credential |          |
|  Wallet Instance  | and Status Attestation      | Verifier |
|                   |---------------------------->|          |
+-------------------+                             +----------+
~~~
Figure 2: Status Attestation Presentation Flow

The Status Attestation is presented along with its digital credential, to prove the non-revocation status of a digital credential to a Verifier.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Terminology

This specification uses the terms "End-User", "Entity" as defined by
OpenID Connect Core [@OpenID.Core], the term "JSON Web Token (JWT)"
defined by JSON Web Token (JWT) {{RFC7519}}.

Digital Credential:
: A set of one or more claims about a subject made by a Credential Issuer.

Credential Issuer:
: Entity that is responsible for the issuance of the Digital Credentials.
The Issuer is responsible for the lifecycle of their issued Digital Credentials
and their validity status.

Verifier:
: Entity that relies on the validity of the Digital Credentials presented to it.
This Entity, also known as a Relying Party, verifies the authenticity and
validity of the Digital Credentials, including their revocation status,
before accepting them.

Wallet Instance:
: The digital Wallet in control of a User, also known as Wallet or Holder.
It securely stores the User's Digital Credentials. It can present Digital Credentials to Verifiers
and request Status Attestations from Issuers under the control of the User.

# Rationale

OAuth Status Lists [@!I-D.looker-oauth-jwt-cwt-status-list] are suitable
for specific scenarios, especially when the Verifier needs to verify the
status of a Digital Credential at a later time after the User has presented the
Digital Credential.

However, there are cases where the Verifier only needs
to check the revocation status of a Digital Credential at the time of
presentation, or situations where the Verifier should not be allowed to
check the status of a Digital Credential over time due to some privacy constraints,
in compliance with national privacy regulations.

For instance, consider a scenario under the European Union's General Data Protection Regulation (GDPR), where a Verifier's repeated access to a Status List to check the revocation status of a Digital Credential could be deemed as excessive monitoring of the End-User's activities. This could potentially infringe upon the End-User's right to privacy, as outlined in Article 8 of the European Convention on Human Rights, by creating a detailed profile of the End-User's interactions and credential usage without explicit consent for such continuous surveillance.

In scenarios where the Verifier, Credential Issuer, and OAuth Status List
Provider are all part of the same domain or operate within a context where
a high level of trust exists between them and the End-User, the OAuth
Status List is the optimal solution; while there might be other cases
where the OAuth Status List facilitates the exposure to the following
privacy risks:

- An OAuth Status List Provider might know the association between a specific
list and a Credential Issuer, especially if the latter issues a
single type of Digital Credential. This could inadvertently reveal the
Status List Provider which list corresponds to which Digital Credential.
- A Verifier retrieves an OAuth Status List by establishing a TCP/IP connection
with an OAuth Status List Provider. This allows the OAuth Status List Provider to
obtain the IP address of the Verifier and potentially link it to a specific
Digital Credential type and Credential Issuer associated with that OAuth Status List.
A malicious OAuth Status List Provider could use internet diagnostic tools, such as Whois
or GeoIP lookup, to gather additional information about the Verifier.
This could inadvertently disclose to the OAuth Status List Provider which
Digital Credential the requester is using and from which Credential Issuer,
information that should remain confidential.

Status Attestations differ significantly from OAuth Status Lists in several ways:

1. **Privacy**: Status Attestations are designed to be privacy-preserving.
They do not require the Verifier to gather any additional information
from third-party entities, thus preventing potential privacy leaks.

2. **Static Verification**: Status Attestations are designed to be
statically provided to Verifiers by Wallet Instance.
Once a Status Attestation is issued, it can be verified without any further
communication with the Credential Issuer or any other party.

3. **Digital Credentials Formats**: Status Attestations are agnostic from the
Digital Credential format to which they are bound.

4. **Trust Model**: Status Attestations operate under a model where
the Verifier trusts the Credential Issuer to provide accurate status information,
while the OAuth Status Lists operate under a model where the Verifier
trusts the Status List Provider to maintain an accurate and up-to-date
list of statuses.

5. **Offline flow**: OAuth Status List can be accessed by a Verifier when
an internet connection is present. At the same time,
OAuth Status List defines
how to provide a static Status List Token, to be included within a
Digital Credential. This requires the Wallet Instance to acquire a
new Digital Credential for a specific presentation. Even if similar to
the OAuth Status List Token, the Status Attestations enable the User to
persistently use their preexistent Digital Credentials, as long as
the linked Status Attestation is available and presented to the
Verifier, and not expired.


# Requirements

The general requirements for the implementation of Status Attestation are listed in this section.
The Status Attestation:

- MUST be presented in conjunction with the Digital Credential.
The Status Attestation MUST be timestamped with its issuance datetime,
always referring to a previous period to the presentation time.
- MUST contain the expiration datetime after which the Digital Credential
MUST NOT be considered valid anymore. The expiration datetime MUST be
superior to the issuance datetime.
- enables offline use cases as it MUST be validated using
a cryptographic signature and the cryptographic public key of the Credential Issuer.

Please note: in this specification the examples and the normative properties
of Attestations are reported in accordance with the JWT standard, while
for the purposes of this specification any Digital Credential or Attestation
format may be used, as long as all attributes and requirements
defined in this specification are satisfied, even using equivalent names
or values.

# Proof of Possession of a Credential

The concept of Proof of Possession (PoP) of a Credential within the framework of the Status Attestation specification encompasses a broader perspective than merely possessing the digital bytes of the Credential. It involves demonstrating rightful control or ownership over the Credential, which can manifest in various forms depending on the technology employed and the nature of the digital Credential itself. For instance, a Credential could be presented visually (de-visu) with a personal portrait serving as a binding element.

While this specification does not prescribe any additional methods for the proof of possession of the Credential, it aims to offer guidance for concrete implementations utilizing common proof of possession mechanisms. This includes, but is not limited to:

1. Having the digital representation of the credential (the bytes).
2. Controlling a private key that corresponds to a public key associated with the Credential, often indicated within the Credential's cnf (confirmation) claim or through a similar mechanism.

The essence of requiring control over the private key and its demonstration through a cryptographic operation (e.g., signing a challenge or a token) is to ensure that the entity in possession of the Credential can execute actions exclusively reserved for the legitimate subject. The dual-layered approach of requiring both possession of the Credential and control over the corresponding private key indeed reinforces the security and integrity of the status attestation process. It also ensures that the entity requesting a Status Attestation is indeed the same entity to which the Credential was originally issued, affirming the authenticity and rightful possession of the Credential.

# Status Attestation Request

The Credential Issuer provides the Wallet Instance with a Status Attestation,
which is bound to a Digital Credential.
This allows the Wallet Instance to present it, along with the Digital Credential itself,
to a Verifier as proof of the Digital Credential's non-revocation status.

The following diagram shows the Wallet Instance requesting a
Status Attestation to a Credential Issuer,
related to a specific Credential issued by the same Credential Issuer.


~~~ ascii-art
+-------------------+                         +--------------------+
|                   |                         |                    |
|  Wallet Instance  |                         | Credential Issuer  |
|                   |                         |                    |
+--------+----------+                         +----------+---------+
         |                                               |
         | HTTP POST /status                             |
         |  credential_pop = [$CredentialPoPJWT]         |
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

The Wallet Instance sends the Status Attestation request to the Credential Issuer.
The request MUST contain the base64url hash value of the Digital Credential, for which the Status Attestation
is requested, and enveloped in a signed object as proof of possession.
The proof of possession MUST be signed with the private key corresponding
to the public key attested by the Credential Issuer and contained within the Digital Credential.

~~~
POST /status HTTP/1.1
Host: issuer.example.org
Content-Type: application/x-www-form-urlencoded

credential_pop = [$CredentialPoPJWT]
~~~

To validate that the Wallet Instance is entitled to request its Status Attestation,
the following requirements MUST be satisfied:

- The Credential Issuer MUST verify the signature of the `credential_pop` object using
the public key contained in the Digital Credential;
- the Credential Issuer MUST verify that it is the legitimate Issuer.

The technical and details about the `credential_pop` object
are defined in the next section.

*TODO CREDENTIAL_POP DEFINITION*

## Status Attestation Request Errors

In cases where a Status Attestation request is made for a Digital Credential that does not exist, has expired, been revoked, or is in any way invalid, or if the HTTP Request is compromised by missing or incorrect parameters, the Credential Issuer is required to respond with an HTTP Response. This response should have a status code of `400` and use `application/json` as the content type, including the following parameters:

- `error`, REQUIRED. The value must be assigned one of the error types as specified in the OAuth 2.0 RFC [Section 5.2](https://tools.ietf.org/html/rfc6749#section-5.2);
- `error_description`, OPTIONAL. Text in human-readable form that offers more details to clarify the nature of the error encountered (for instance, changes in some attributes, reasons for revocation, other).

Below a non-normative example of an HTTP Response with an error.

~~~
  HTTP/1.1 400 Bad Request
  Content-Type: application/json;charset=UTF-8

  {
    "error": "invalid_request"
    "error_description": "The signature of credential_pop JWT is not valid"
  }
~~~

## Digital Credential Proof of Possession

The Wallet Instance that holds a Digital Credential, when requests a Status Attestation,
MUST demonstrate the proof of possession of the Digital Credential to the Credential Issuer.

The proof of possession is made by enclosing the Digital Credential in an
object (JWT) signed with the private key that its related public key is referenced in the Digital Credential.

Below is a non-normative example of a Credential proof of possession with
the JWT headers and payload are represented without applying signature and
encoding, for better readability:

~~~
{
    "alg": "ES256",
    "typ": "status-attestation-request+jwt",
    "kid": $CREDENTIAL-CNF-JWKID
}
.
{
    "iss": "0b434530-e151-4c40-98b7-74c75a5ef760",
    "aud": "https://issuer.example.org/status-attestation-endpoint",
    "iat": 1698744039,
    "exp": 1698834139,
    "jti": "6f204f7e-e453-4dfd-814e-9d155319408c",
    "credential_hash": $Issuer-Signed-JWT-Hash
    "credential_hash_alg": "sha-256",
}
~~~


When the JWT format is used, the JWT MUST contain the parameters defined in the following table.

| JOSE Header | Description | Reference |
| --- | --- | --- |
| **typ** | It MUST be set to `status-attestation-request+jwt` | {{RFC7516}} Section 4.1.1 |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or any symmetric algorithm (MAC) identifier. | {{RFC7516}} Section 4.1.1 |
| **kid** | Unique identifier of the JWK used for the signature of the Status Attestation Request, it MUST match the one contained in the Credential `cnf.jwk`. | {{RFC7515}} |

| JOSE Payload | Description | Reference |
| --- | --- | --- |
| **iss** | Wallet identifier. | {{RFC9126}}, {{RFC7519}} |
| **aud** | It MUST be set with the Credential Issuer Status Attestation endpoint URL as value that identify the intended audience | {{RFC9126}}, {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. It MUST be superior to the value set for `iat`. | {{RFC9126}}, {{RFC7519}}, {{RFC7515}} |
| **iat** | UNIX Timestamp with the time of JWT issuance. | {{RFC9126}}, {{RFC7519}} |
| **jti** | Unique identifier for the JWT.  | {{RFC7519}} Section 4.1.7 |
| **credential_hash** | Hash value of the Digital Credential the Status Attestation is bound to. | this specification |
| **credential_hash_alg** |  The Algorithm used of hashing the Digital Credential to which the Status Attestation is bound. The value SHOULD be set to `sha-256`. | this specification |


# Status Attestation

When a Status Attestation is requested to a Credential Issuer, the
Issuer checks the status of the Digital Credential and creates a Status Attestation bound to it.

If the Digital Credential is valid, the Credential Issuer creates a new Status Attestation, which a non-normative example is given below.

~~~
{
    "alg": "ES256",
    "typ": "status-attestation+jwt",
    "kid": $ISSUER-JWKID
}
.
{
    "iss": "https://issuer.example.org",
    "iat": 1504699136,
    "exp": 1698830439,
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
| **typ** | It MUST be set to `status-attestation+jwt`. | {{RFC7515}}, {{RFC7517}} and this specification |
| **kid** | Unique identifier of the Issuer JWK. | {{RFC7515}} |

| JOSE Payload | Description | Reference |
| --- | --- | --- |
| **iss** | It MUST be set to the identifier of the Issuer. | {{RFC9126}}, {{RFC7519}} |
| **iat** | UNIX Timestamp with the time of the Status Attestation issuance. | {{RFC9126}}, {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. It MUST be superior to the value set for `iat`. | {{RFC9126}}, {{RFC7519}}, {{RFC7515}} |
| **credential_hash** | Hash value of the Digital Credential the Status Attestation is bound to. | this specification |
| **credential_hash_alg** | The Algorithm used of hashing the Digital Credential to which the Status Attestation is bound. The value SHOULD be set to `sha-256`. | this specification |
| **cnf** | JSON object containing the cryptographic key binding. The `cnf.jwk` value MUST match with the one provided within the related Digital Credential. | {{RFC7800}} Section 3.1 |


# Status Attestation Response

If the Status Attestation is requested for a non-existent, expired, revoked or invalid Digital Credential, the
Credential Issuer MUST respond with an HTTP Response with the status code set to 404.

If the Digital Credential is valid, the Credential Issuer MUST return an HTTP status code of 201 (Created), with the content type set to `application/json`. The response MUST include a JSON object with a member named `status_attestation`, which contains the Status Attestation for the Wallet Instance, as illustrated in the following non-normative example:

~~~
HTTP/1.1 201 Created
Content-Type: application/json

{
    "status_attestation": "eyJhbGciOiJFUzI1Ni ...",
}
~~~
*TODO STATUS_ATTESTATION DEFINITION*


# Credential Issuers Supporting Status Attestations

This section outlines how Credential Issuers support Status Attestations, detailing the necessary metadata and practices to integrate into their systems.

## Credential Issuer Metadata

The Credential Issuers that uses the Status Attestations MUST include in their
OpenID4VCI [@!OpenID.VCI] metadata the claims:

- `status_attestation_endpoint`. REQUIRED. It MUST be an HTTPs URL indicating the endpoint where the Wallet Instances can request Status Attestations.
- `credential_hash_alg_supported`. REQUIRED. The supported Algorithm used by the Wallet Instance to hash the Digital Credential for which the Status Attestation is requested,  using one of the hash algorithms listed in the [IANA - Named Information Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg).


## Issued Digital Credentials

The Credential Issuers that uses the Status Attestations SHOULD include in the
issued Digital Credentials the object `status` with the
JSON member `status_attestation` set to a JSON Object containing the following
member:

- `credential_hash_alg`. REQUIRED. The Algorithm used of hashing the Digital Credential to which the Status Attestation is bound, using one of the hash algorithms listed in the [IANA - Named Information Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg). Among the hash algorithms, `sha-256` is recommended and SHOULD be implemented by all systems.


The non-normative example of an unsecured payload of
an SD-JWT VC is shown below.

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
    "status_attestation": {
        "credential_hash_alg": "sha-256",
    }
 }
}
~~~

### Credential Issuer Implementation Considerations

When the Digital Credential is issued, the Credential Issuer SHOULD calculate the hash value using the algorithm specified in `status.status_attestation.credential_hash_alg` and store this information in its database. This practice enhances efficiency by allowing the Credential Issuer to quickly compare the requested `credential_hash with the pre-calculated one, when processing Status Attestation requests made by Holders.

# Presenting Status Attestations

The Wallet Instance that provides the Status Attestations using [@OpenID4VP], SHOULD include in the
`vp_token` JSON array, as defined in [@OpenID4VP], the Status Attestation along with the
related Digital Credential.

Since the Wallet may request one or more Status Attestations, issued by the same Credential Issuer, the `credential_pop` object MUST be an array.

The Verifier that receives a Digital Credential supporting the Status Attestation,
SHOULD:

- Decode and validate the Digital Credential;
- check the presence of `status.status_attestation` in the Digital Credential. If true, the Verifier SHOULD:
  - produce the hash of the Digital Credential using the hashing algorithm configured in `status.status_attestation.credential_hash_alg`;
  - decode all the Status Attestations provided in the presentation, by matching the JWS Header parameter `typ` set to `status-attestation+jwt` and looking for the `credential_hash` value that matches with the hash produced at the previous point;
  - evaluate the validity of the Status Attestation.

Please note: The importance of checking the revocation status of Digital Credentials as a 'SHOULD' rather than a 'MUST' for a Verifier
who gets Status Attestation for the Digital Credential stems from the fact that the decision of a Verifier to check the revocation status
of Digital Credentials is not absolute and can be influenced by numerous variables. Consider as an example the case of age-over x;
even if it has expired, it may still perform its intended purpose. As a result, the expiration status alone does not render it invalid.
The adaptability recognizes that the need to verify revocation status may not always coincide with the actual usability of a Digital Credential,
allowing Verifiers to examine and make educated conclusions based on a variety of scenarios.


# Security Considerations

TODO Security

# Privacy Considerations

In the design and implementation of Status Attestations, particular attention has been paid to privacy considerations to ensure that the system is respectful of user privacy and compliant with relevant regulations.

## Privacy Consideration: Status Attestation Request Opacity

The request for a status attestation does not transmit the digital credential for which the status is being attested. Instead, it includes a proof of possession (PoP) of the credential that is only interpretable by the credential issuer who issued the digital credential for which the status attestation is requested. This PoP can be achieved through a cryptographic signature using the public key contained within the digital credential over the request. This method is essential for preventing the potential for fraudulent requests intended to mislead or disclose sensitive information to unintended parties. By separating the digital credential from the status attestation request, the system ensures that the request does not inadvertently disclose any information about the digital credential or its holder. This strategy significantly enhances the privacy and security of the system by preventing the attestation process from being used to collect information about digital credentials or their holders through deceptive requests.

## Privacy Consideration: Opacity of Status Attestation Content

An important privacy consideration is how the status attestation is structured to ensure it does not reveal any information about the user or the holder of the digital credential. The status attestation is crafted to prove only the vital information needed to verify the current state of a digital credential, moving beyond simple revocation or suspension checks. This is done by focusing the attestation content on the credential's present condition and the method for its verification, rather than on the identity of the credential's holder. This approach is key in keeping the user's anonymity intact, making sure that the status attestation can be applied in various verification situations without risking the privacy of the people involved.

## Unlinkability and Reusability of Status Attestations

Status Attestations are designed to uphold privacy by allowing verifiers to operate independently, without the need for interaction or information disclosure to third-party entities or other verifiers. This design is pivotal in ensuring unlinkability between verifiers, where actions taken by one verifier cannot be correlated or linked to actions taken by another. Verifiers can directly validate the status of a digital credential through the Status Attestation, eliminating the need for external communication. This mechanism is key in protecting the privacy of individuals whose credentials are being verified, as it significantly reduces the risk of tracking or profiling based on verification activities across various services.

While Status Attestations facilitate unlinkability, they are not inherently "single use." The specification accommodates the batch issuance of multiple status attestations, which can be single-use. However, particularly for offline interactions, a single attestation may be utilized by numerous verifiers. This flexibility ensures that Status Attestations can support a wide range of verification scenarios, from one-time validations to repeated checks by different entities, without compromising the privacy or security of the credential holder.

## Untrackability by Digital Credential Issuers and the "Phone Home" Problem

A fundamental aspect of the privacy-preserving attributes of Status Attestations is their ability to address the "phone home" problem, which is the prevention of tracking by digital credential issuers. Traditional models often require verifiers to query a central status list or contact the issuer directly, a process that can inadvertently allow issuers to track when and where a digital credential is verified. Status Attestations, however, encapsulate all necessary verification information within the attestation itself. This design choice ensures that credential issuers are unable to monitor the verification activities of their issued digital credentials, thereby significantly enhancing the privacy of the credential holder. By removing the need for real-time communication with the issuer for status checks, Status Attestations effectively prevent the issuer from tracking verification activities, further reinforcing the system's dedication to protecting user privacy.

## Minimization of Data Exposure

The Status Attestations are designed around the data minimization principle. Data minimization ensures that only the necessary information required for the scope of attesting the non revocation status of the digital credential. This minimizes the exposure of potentially sensitive data.

## Resistance to Enumeration Attacks

The design of Status Attestations incorporates measures to resist enumeration attacks, where an adversary attempts to gather information by systematically verifying different combinations of data. By implementing robust cryptographic techniques and limiting the information contained in status attestations, the system reduces the feasibility of such attacks. This consideration is vital for safeguarding the privacy of the credential holders and for ensuring the integrity of the verification process.

Status Attestations are based on a privacy-by-design approach, reflecting a deliberate effort to balance security and privacy needs in the Digital Credential ecosystem.

# IANA Considerations

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by {{RFC7519}}.

*  Claim Name: `credential_format`
*  Claim Description: The Digital Credential format the Status Attestation is bound to.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#digital-credential-proof-of-possession) of this specification ]]

<br/>

*  Claim Name: `credential`
*  Claim Description: The Digital Credential the Status Attestation is bound to.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#digital-credential-proof-of-possession) of this specification ]]

<br/>

*  Claim Name: `credential_hash`
*  Claim Description: Hash value of the Digital Credential the Status Attestation is bound to.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#status-attestation) of this specification ]]

<br/>

*  Claim Name: `credential_hash_alg`
*  Claim Description: The Algorithm used of hashing the Digital Credential to which the Status Attestation is bound.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#status-attestation) of this specification ]]

## Media Type Registration

This section requests registration of the following media types [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@RFC6838].

To indicate that the content is an JWT-based Status List:

  * Type name: application
  * Subtype name: status-attestation-request+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary; A JWT-based Status Attestation Request object is a JWT; JWT values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') characters.
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for updated status information of tokens
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

To indicate that the content is an CWT-based Status List:

  * Type name: application
  * Subtype name: status-attestation+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for status attestation of tokens and Digital Credentials
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
- Emanuele De Cupis
- Riccardo Iaconelli
- Victor Näslund
- Giada Sciarretta
- Amir Sharif


# Document History

TODO changelog.
