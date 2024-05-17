---
title: "OAuth Status Assertions"
abbrev: "OAuth Status Assertions"
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
  RFC8152: RFC8152
  RFC8392: RFC8392
  RFC8747: RFC8747
  RFC9126: RFC9126

informative:

--- abstract

Status Assertion is a signed object that demonstrates the validity status of a
digital credential.
These assertions are periodically provided
to holders, who can present these to verifier along
with the corresponding digital credentials.
The approach outlined in this document
makes the verifier able to check the non-revocation of a digital credential
without requiring to query any third-party entities.

--- middle

# Introduction

Status Assertions ensure the non-revocation of digital
credentials, whether in JSON Web Tokens (JWT) or CBOR Web Tokens (CWT)
format. Status Assertions function
similarly to OCSP Stapling, allowing wallet instances to present
time-stamped assertions from the Credential Issuer.
The approach outlined in this specification enables the
verification of credentials against revocation without
direct queries to third-party systems.
This enhances privacy, reduces latency, and
facilitates offline verification.

The figure below illustrates the process by which a Wallet Instance
requests and obtains a Status Assertion from the credential issuer.

~~~ ascii-art
+-----------------+                             +-------------------+
|                 | Requests Status Assertion   |                   |
|                 |---------------------------->|                   |
| Wallet Instance |                             | Credential Issuer |
|                 | Status Assertion            |                   |
|                 |<----------------------------|                   |
+-----------------+                             +-------------------+
~~~
**Figure 1**: Status Assertion Issuance Flow.

The figure below illustrates the process by which a Wallet Instance
presents the Status Assertion along with the corresponding digital credential,
to prove the non-revocation status of the digital credential to a verifier.

~~~ ascii-art
+-- ----------------+                             +----------+
|                   | Presents Digital Credential |          |
|  Wallet Instance  | and Status Assertion        | Verifier |
|                   |---------------------------->|          |
+-------------------+                             +----------+
~~~
**Figure 2**: Status Assertion Presentation Flow.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Terminology

This specification uses the terms "End-User", "Entity" as defined by
OpenID Connect Core [@OpenID.Core], the term "JSON Web Token (JWT)"
defined by JSON Web Token (JWT) {{RFC7519}}, the term "CBOR Web Token (CWT)" defined in {{RFC8392}}.

Holder:
: An entity that receives Verifiable Credentials and has
control over them to present them to the Verifiers as Verifiable Presentations.

Digital Credential:
: A set of one or more claims about a subject made by a Credential Issuer.
Alternative names are "Verifiable Credential" or "Credential".

Credential Issuer:
: Entity that is responsible for the issuance of the Digital Credentials.
The Issuer is responsible for the lifecycle of their issued
Digital Credentials and their validity status.

Holder:
: An entity that receives Verifiable Credentials and has control over
them to present them to the Verifiers as Verifiable Presentations.

Verifier:
: Entity that relies on the validity of the Digital Credentials presented to it.
This Entity, also known as a Relying Party, verifies the authenticity and
validity of the Digital Credentials, including their revocation status,
before accepting them.

Wallet Instance:
: The digital Wallet in control of a User, also known as Wallet or Holder.
It securely stores the User's Digital Credentials. It can present
Digital Credentials to Verifiers
and request Status Assertions from Issuers under the control of the User.

# Rationale

OAuth Status Lists [@!I-D.looker-oauth-jwt-cwt-status-list] are suitable
for specific scenarios, especially when the Verifier needs to verify the
status of a Digital Credential at a later time after the User has presented the
Digital Credential.

There are cases where the Verifier only needs
to check the revocation status of a Digital Credential at the time of
presentation, or situations where the Verifier should not be allowed to
check the status of a Digital Credential over time due to some privacy constraints,
in compliance with national privacy regulations.

For instance, consider a scenario where a Verifier's repeated access to a
Status List to check the revocation status of a Digital Credential could
be deemed as excessive monitoring of the End-User's activities.
This could potentially infringe upon the End-User's right to privacy,
as outlined in [Article 8 of the European Convention on Human Rights]
(https://www.echr.coe.int/documents/convention_eng.pdf) and
in the the European Union's General Data Protection Regulation
([GDPR](https://gdpr-info.eu/)),
by creating a detailed profile of the End-User's
credential status without explicit consent for such continuous surveillance.

In scenarios where the Verifier, Credential Issuer, and OAuth Status List
Provider are all part of the same domain or operate within a context where
a high level of trust exists between them and the End-User, the OAuth
Status List is the optimal solution; while there might be other cases
where the OAuth Status List facilitates the exposure to the following
privacy risks:

- An OAuth Status List Provider might know the association between a specific
status list and a Credential Issuer, especially if the latter issues a
single type of Digital Credential. This could inadvertently reveal the
OAusth Status List Provider information about how a Digital Credential
corresponds to a status list.
- A Verifier retrieves an OAuth Status List by establishing a TCP/IP connection
with an OAuth Status List Provider. This allows the OAuth Status List Provider to
obtain the IP address of the Verifier and potentially link it to a specific
Digital Credential type and Credential Issuer associated with that OAuth Status List.
A malicious OAuth Status List Provider could use internet diagnostic tools, such as Whois
or GeoIP lookup, to gather additional information about the Verifier.
This could inadvertently disclose to the OAuth Status List Provider which
Digital Credential the requester is using and from which Credential Issuer,
information that should remain confidential.

Status Assertions differ significantly from OAuth Status Lists in several ways:

1. **Privacy**: Status Assertions are designed to be privacy-preserving.
Verifier exchanges the Status Assertions directly with the Holder,
not requiring the Verifier to gather any additional information
from third-party entities. Once a Status Assertion is issued,
it can be verified without any further
communication with the Credential Issuer or any other party,
thus preventing potential privacy leaks.

2. **Static Verification**: Status Assertions are designed to be
statically provided to Verifiers by Wallet Instance.

3. **Digital Credentials Formats**: Status Assertions are agnostic from the
Digital Credential format to which they are bound.

4. **Trust Model**: Status Assertions operate under a model where
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
the OAuth Status List Token, the Status Assertions enable the User to
persistently use their preexistent Digital Credentials, as long as
the linked Status Assertion is available and presented to the
Verifier, and not expired.

6. **Real-time validation**: OAuth Status Lists provide the possibility
to do real-time validation of the Digital Credential status. To support
the real-time status validation use cases, a Wallet MAY implement strategy
to request a new Status Assertion before sending it to the Verifier.

# Requirements

The general requirements for the implementation of Status Assertion are
listed in this section. The Status Assertion:

- MUST be presented in conjunction with the Digital Credential.
The Status Assertion MUST be timestamped with its issuance datetime,
using a timestamp which is later then the time of presentation issuance;
- MUST contain the expiration datetime after which the Digital Credential
MUST NOT be considered valid anymore. The expiration datetime MUST be
superior to the Status Assertion issuance datetime and it MUST end before
the expiration of the Credential;
- MUST enable the offline use cases by employing validation using
a cryptographic signature and the cryptographic public key of the
Credential Issuer.

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
2. Controlling a private key that corresponds to a public key associated
with the Credential, often indicated within the Credential's cnf
(confirmation) claim or through a similar mechanism.

The essence of requiring control over the private key and its
demonstration through a cryptographic operation
(e.g., signing a challenge or a token) is to ensure that the entity in
possession of the Credential can execute actions exclusively reserved
for the legitimate subject. The dual-layered approach of requiring both
possession of the Credential and control over the corresponding private
key indeed reinforces the security and integrity of the status assertion
process. It also ensures that the entity requesting a Status Attestation
is indeed the same entity to which the Credential was originally issued,
affirming the authenticity and rightful possession of the Credential.

# Status Assertion Request

The Credential Issuer provides the Wallet Instance with a Status Assertion,
which is bound to a Digital Credential.
This allows the Wallet Instance to present it, along with the
Digital Credential itself,
to a Verifier as proof of the Digital Credential's non-revocation status.

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
- The request MUST contain the base64url encoded hash value of the Digital Credential,
for which the Status Assertion is requested, and enveloped in a signed
Status Assertion Request object.
- The Status Assertion Request object MUST be signed with the private key corresponding
to the confirmation claim assigned by the Issuer and contained within
the Digital Credential.

When the JWT or CWT format are used, the JWT/CWT MUST contain the parameters defined in the following table.

| Header | Description | Reference |
| --- | --- | --- |
| **typ** | It MUST be set to `status-attestation+jwt` when JWT format is used. It MUST be set to `status-attestation+cwt` when CWT format is used. | {{RFC7516}} Section 4.1.1 |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or any symmetric algorithm (MAC) identifier. | {{RFC7516}} Section 4.1.1 |
| **kid** | Unique identifier of the `JWK or` `Cose_Key` used for the signature of the Status Attestation Request, it MUST match the one contained in the Credential. | {{RFC7515}} |

| Payload | Description | Reference |
| --- | --- | --- |
| **iss** | Wallet identifier. The Wallet identifier value is supposed to be used for identifying a wallet; therefore, it is out of scope for this specs, considering that it may simply be an ephemeral value. | {{RFC9126}}, {{RFC7519}} |
| **aud** | It MUST be set with the Credential Issuer Status Attestation endpoint URL as value that identify the intended audience | {{RFC9126}}, {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. It MUST be superior to the value set for `iat`  . | {{RFC9126}}, {{RFC7519}}, {{RFC7515}} |
| **iat** | UNIX Timestamp with the time of JWT/CWT issuance. | {{RFC9126}}, {{RFC7519}} |
| **jti** | Unique identifier for the JWT.  | {{RFC7519}} Section 4.1.7 |
| **credential_hash** | Hash value of the Digital Credential the Status Attestation is bound to. | this specification |
| **credential_hash_alg** |  The Algorithm used of hashing the Digital Credential to which the Status Attestation is bound. The value SHOULD be set to `sha-256`. | this specification |

Below is a non-normative example of a Status Assertion Request with
the JWT headers and payload are represented without applying signature and
encoding, for better readability:

~~~
{
    "alg": "ES256",
    "typ": "status-assertion-request+jwt",
    "kid": $CREDENTIAL-CNF-JWKID
}
.
{
    "iss": "0b434530-e151-4c40-98b7-74c75a5ef760",
    "aud": "https://issuer.example.org/status-assertion-endpoint",
    "iat": 1698744039,
    "exp": 1698830439,
    "jti": "6f204f7e-e453-4dfd-814e-9d155319408c",
    "credential_hash": $Issuer-Signed-JWT-Hash
    "credential_hash_alg": "sha-256",
}
~~~

Below is a non-normative example of a Status Assertion Request object in CWT format
represented in CBOR diagnostic notation format {{RFC8152}}, where the CWT headers
and payload are presented without applying signature and encoding for better readability:

~~~
   [
       / protected / << {
       / alg / 1: -7 / ES256 /
       / typ / 16: -7 / status-attestation-request+cwt /
       / kid / 4: h'3132' / $CREDENTIAL-CNF-CWKID /
     } >>,
     / unprotected / {
     },
     / payload / << {
       / iss    / 1: 0b434530-e151-4c40-98b7-74c75a5ef760 /,
       / aud    / 3: https://issuer.example.org/status-attestation-endpoint /,
       / iat    / 6: 1698744039 /,
       / exp    / 4: 1698830439 /,
       / cti    / 7: 6f204f7e-e453-4dfd-814e-9d155319408c /,
       / credential_hash / 8: $Issuer-Signed-JWT-Hash /,
       / credential_hash_alg / 9: sha-256 /
     } >>,
   ]
~~~

Below a non-normative example representing a Status Assertion Request array with a
single Status Assertion Reuqest object in JWT format.

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
HTTP/1.1 201 Created
Content-Type: application/json

{
    "status_assertion_responses": ["${base64url(json({typ: status-assertion+jwt, ...}))}.payload.signature", ... ]
}
~~~

The member `status_assertion_responses` MUST be an array of strings,
where each of them represent a Status Assertion Response object,
as defined in
[the section Status Assertion](#status-assertion)or a Status Assertion Error object,
as defined in [the section Status Error](#status-error).
For each entry in the `status_assertion_responses` array, the following requirements are met:
- Each element in the array MUST match the corresponding element in the request array at the same index to which it is related.
- Each element MUST contain the error or the status of the assertion using the `typ` member.
set to "status-assertion-error+{jwt,cwt}" or "status-assertion+{jwt,cwt}", depending by the object type.
- The corresponding entry in the response MUST be of the same type as requested. For example,
if the entry in the request is "jwt",
then the entry at the same position in the response must also be "jwt".

# Status Assertion Error

If the Status Assertion is requested for a non-existent, expired, revoked
or invalid Digital Credential, the
Credential Issuer MUST respond with an HTTP Response with the status
code set to 404.

TBD schema of the errors.

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
    "credential_hash": $CREDENTIAL-HASH,
    "credential_hash_alg": "sha-256",
    "cnf": {
        "jwk": {...}
    }
}
~~~

The Status Assertion MUST contain the parameters defined below.

| Header Parameter Name | Description | Reference |
| --- | --- | --- |
| **alg** | A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be set to `none` or to a symmetric algorithm (MAC) identifier. | {{RFC7515}}, {{RFC7517}} |
| **typ** | It MUST be set to `status-attestation+jwt` when JWT format is used. It MUST be set to `status-attestation+cwt` when CWT format is used. | {{RFC7515}}, {{RFC7517}} and this specification |
| **kid** | Unique identifier of the Credential Issuer JWK | {{RFC7515}} |

| Payload Parameter Name | Description | Reference |
| --- | --- | --- |
| **iss** | It MUST be set to the identifier of the Issuer. | {{RFC9126}}, {{RFC7519}} |
| **iat** | UNIX Timestamp with the time of the Status Assertion issuance. | {{RFC9126}}, {{RFC7519}} |
| **exp** | UNIX Timestamp with the expiration time of the JWT. It MUST be greater than the value
set for `iat`. | {{RFC9126}}, {{RFC7519}}, {{RFC7515}} |
| **credential_hash** | Hash value of the Digital Credential the Status Assertion is bound to. | this specification |
| **credential_hash_alg** | The Algorithm used of hashing the Digital Credential to which the Status Assertion is bound. The value SHOULD be set to `sha-256`. | this specification |
| **cnf** | JSON object containing confirmation methods. The sub-member contained within `cnf` member, such as `jwk` for JWT and `Cose_Key` for CWT, MUST match with the one provided within the related Digital Credential. Other confirmation methods can be utilized when the referenced Digital Credential supports them, in accordance with the relevant standards. | {{RFC7800}} Section 3.1, {{RFC8747}} Section 3.1 |


# Interoperability of Credential Issuers Supporting Status Assertions

This section outlines how Credential Issuers support Status Assertions,
detailing the necessary metadata and practices to integrate into their systems.

## Credential Issuer Metadata

The Credential Issuers that uses the Status Assertions MUST include in their
OpenID4VCI [@!OpenID.VCI] metadata the claims:

- `status_assertion_endpoint`. REQUIRED. It MUST be an HTTPs URL indicating
the endpoint where the Wallet Instances can request Status Assertions.
- `credential_hash_alg_supported`. REQUIRED. The supported Algorithm used by
the Wallet Instance to hash the Digital Credential for which the
Status Assertion is requested,  using one of the hash algorithms listed
in the
[IANA - Named Information Hash Algorithm Registry]
(https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg).


## Issued Digital Credentials

The Credential Issuers that uses the Status Assertions SHOULD include in the
issued Digital Credentials the object `status` with the
JSON member `status_assertion` set to a JSON Object containing the following
member:

- `credential_hash_alg`. REQUIRED. The Algorithm used of hashing the
Digital Credential to which the Status Assertion is bound, using one of the
hash algorithms listed in the
[IANA - Named Information Hash Algorithm Registry]
(https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg).
Among the hash algorithms, `sha-256` is recommended and
SHOULD be implemented by all systems.


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
    "status_assertion": {
        "credential_hash_alg": "sha-256",
    }
 }
}
~~~

### Credential Issuer Implementation Considerations

When the Digital Credential is issued, the Credential Issuer SHOULD
calculate the hash value using the algorithm specified in
`status.status_assertion.credential_hash_alg` and store this information
in its database. This practice enhances efficiency by allowing the
Credential Issuer to quickly compare the requested
`credential_hash` with the pre-calculated one, when processing
Status Assertion requests made by Holders.

# Presenting Status Assertions

The Wallet Instance that provides the Status Assertions using [@OpenID4VP], SHOULD include in the
`vp_token` JSON array, as defined in [@OpenID4VP], the Status Assertion along with the
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

Please note: The importance of checking the revocation status of
Digital Credentials as a 'SHOULD' rather than a 'MUST' for a Verifier
who gets Status Assertion for the Digital Credential stems from the
fact that the decision of a Verifier to check the revocation status
of Digital Credentials is not absolute and can be influenced by
numerous variables. Consider as an example the case of age-over x;
even if it has expired, it may still perform its intended purpose.
As a result, the expiration status alone does not render it invalid.
The adaptability recognizes that the need to verify revocation status
may not always coincide with the actual usability of a Digital Credential,
allowing Verifiers to examine and make educated conclusions based on a
variety of scenarios.


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
possession (PoP) of the credential that is only interpretable by the
Credential Issuer who issued the digital credential for which the
Status Assertion is requested. This PoP can be achieved through a
cryptographic signature using the public key contained within the
Digital Credential over the request. This method is essential for
preventing the potential for fraudulent requests intended to mislead or
disclose sensitive information to unintended parties. By separating the
Digital Credential from the status assertion request, the system ensures
that the request does not inadvertently disclose any information about
the Digital Credential or its holder. This strategy significantly
enhances the privacy and security of the system by preventing the
assertion process from being used to collect information about
Digital Credentials or their holders through deceptive requests.

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
disclosure to third-party entities or other verifiers. This design is
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
Traditional models often require verifiers to query a central status
list or contact the issuer directly, a process that can inadvertently
allow Credential Issuers to track when and where a Digital Credential
is verified. Status Assertions, however, encapsulate all necessary
verification information within the assertion itself. This design choice
ensures that Credential Issuers are unable to monitor the verification
activities of their issued Digital Credentials, thereby significantly
enhancing the privacy of the Holder. By removing the need for real-time
communication with the issuer for status checks, Status Assertions
effectively prevent the issuer from tracking verification activities,
further reinforcing the system's dedication to protecting user privacy.

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
the privacy of the credential holders and for ensuring the integrity of
the verification process.

Status Assertions are based on a privacy-by-design approach, reflecting
a deliberate effort to balance security and privacy needs in the
Digital Credential ecosystem.

# IANA Considerations

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by {{RFC7519}}.

*  Claim Name: `credential_format`
*  Claim Description: The Digital Credential format the Status Assertion is bound to.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#digital-credential-proof-of-possession) of this specification ]]

<br/>

*  Claim Name: `credential`
*  Claim Description: The Digital Credential the Status Assertion is bound to.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#digital-credential-proof-of-possession) of this specification ]]

<br/>

*  Claim Name: `credential_hash`
*  Claim Description: Hash value of the Digital Credential the Status Assertion is bound to.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#status-assertion) of this specification ]]

<br/>

*  Claim Name: `credential_hash_alg`
*  Claim Description: The Algorithm used of hashing the Digital Credential to which the Status Assertion is bound.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#status-assertion) of this specification ]]

## Media Type Registration

This section requests registration of the following media types [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@RFC6838].

To indicate that the content is an JWT-based Status List:

  * Type name: application
  * Subtype name: status-assertion-request+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary; A JWT-based Status Assertion Request object is a JWT; JWT values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') characters.
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
  * Subtype name: status-assertion+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for status assertion of tokens and Digital Credentials
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
- Marina Adomeit
- Victor Näslund
- Giada Sciarretta
- Amir Sharif


# Document History


-02

* Name of the draft changed from `OAuth Status Attestations` to `OAuth Status Assertions`
