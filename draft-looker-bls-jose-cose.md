%%%
title = "Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE"
ipr= "none"
area = "Internet"
workgroup = "none"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Individual-Draft"
value = "draft-looker-bls-jose-cose-latest"
status = "informational"

[[author]]
initials = "T."
surname = "Looker"
fullname = "Tobias Looker"
#role = "editor"
organization = "Mattr"
  [author.address]
  email = "tobias.looker@mattr.global"
%%%

.# Abstract

This specification defines how to represent cryptographic keys for the pairing friendly elliptic curve known as Barreto-Lynn-Scott, for use with in the key representation formats of JSON Web Key (JWK) and COSE (COSE_Key).

{mainmatter}

# Introduction

This specification defines how to represent cryptographic keys for the pairing friendly elliptic curve known as Barreto-Lynn-Scott, for use within the key representation formats of JSON Web Key (JWK) and COSE (COSE_Key). The elliptic curve and associated algorithm are registered in appropriate IANA JOSE and COSE registries.

## Bls12-381 Curve

The following definitions apply to the pairing friendly elliptic curve known as Barreto-Lynn-Scott (BLS) featuring an embedding degree 12 with 381-bit p "BLS12-381".

### Bls12381G1 JSON Web Key (JWK) Representation

A cryptographic key on this curve in the subgroup of G1 defined as `E(GF(p))` of order r, is represented in a JSON Web Key (JWK) [RFC7517] using the following values:

- "kty": "OKP"
- "crv": "Bls12381G1"

plus the "x" value to represent the curve point for the public key.  The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09] [DPFC09] and MUST be base64url encoded without padding as defined in [RFC7515] Appendix C.

### Bls12381G1 COSE_Key Representation

A cryptographic key on this curve in the subgroup of G1 defined as `E(GF(p))` of order r, is represented in a COSE_Key [RFC8152] using the following values:

- "kty" (1): "OKP" (1)
- "crv" (-1): "Bls12381G1" (13)

plus the "x" (-2) value to represent the curve point for the key. The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09].

### Bls12381G2 JSON Web Key (JWK) Representation

A cryptographic key on this curve in the subgroup of G2 defined as `E(GF(p^2))` of order r, is represented in a JSON Web Key (JWK) [RFC7517] using the following values:

- "kty": "OKP"
- "crv": "Bls12381G2"

plus the "x" (-2) value to represent the curve point for the key. The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09].

### Bls12381G2 COSE_Key Representation

A cryptographic key on this curve in the subgroup of G2 defined as `E(GF(p^2))` of order r, is represented in a COSE_Key [RFC8152] using the following values:

- "kty" (1): "OKP" (1)
- "crv" (-1): "Bls12381G2" (14)

plus the "x" (-2) value to represent the curve point for the key. The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09].

## Bls48-581 Curve

The following definitions apply to the pairing friendly elliptic curve known as Barreto-Lynn-Scott (BLS) featuring an embedding degree 48 with 581-bit p "BLS12-381".

### Bls48581G1 JSON Web Key (JWK) Representation

A cryptographic key on this curve in the subgroup of G1 defined as `E(GF(p))` of order r, is represented in a JSON Web Key (JWK) [RFC7517] using the following values:

- "kty": "OKP"
- "crv": "Bls48581G1"

plus the "x" value to represent the curve point for the public key.  The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09] and MUST be base64url encoded without padding as defined in [RFC7515] Appendix C.

### Bls48581G1 COSE_Key Representation

A cryptographic key on this curve in the subgroup of G1 defined as `E(GF(p))` of order r, is represented in a COSE_Key [RFC8152] using the following values:

- "kty" (1): "OKP" (1)
- "crv" (-1): "Bls48581G1" (15)

plus the "x" (-2) value to represent the curve point for the key. The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09].

### Bls48581G2 JSON Web Key (JWK) Representation

A cryptographic key on this curve in the subgroup of G2 defined as `E(GF(p^8))` of order r, is represented in a JSON Web Key (JWK) [RFC7517] using the following values:

- "kty": "OKP"
- "crv": "Bls48581G2"

plus the "x" (-2) value to represent the curve point for the key. The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09].

### Bls48581G2 COSE_Key Representation

A cryptographic key on this curve in the subgroup of G2 defined as `E(GF(p^8))` of order r, is represented in a COSE_Key [RFC8152] using the following values:

- "kty" (1): "OKP" (1)
- "crv" (-1): "Bls48581G2" (16)

plus the "x" (-2) value to represent the curve point for the key. The "x" value MUST be encoded using the Z-Cash serialization defined in [DPFC09].

# Security Considerations

See [DPFC09] for additional details about security considerations of the curves used.  Implementers should also consider section 9 of [RFC7517] when implementing this work.

# IANA Considerations

## JSON Web Key (JWK) Elliptic Curve Registrations

This section registers the following value in the IANA "JSON Web Key Elliptic Curve" registry [IANA.JOSE.Curves].

Bls12381G1

- Curve Name: Bls12381G1
- Curve Description: 381 bit with an embedding degree of 12 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E(GF(p))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.1 of [[ this specification ]]

Bls12381G2

- Curve Name: Bls12381G2
- Curve Description: 381 bit with an embedding degree of 12 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E'(GF(p^2))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.3 of [[ this specification ]]

Bls48581G1

- Curve Name: Bls48581G1
- Curve Description: 581 bit with an embedding degree of 48 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E(GF(p))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.5 of [[ this specification ]]

Bls48581G2

- Curve Name: Bls48581G2
- Curve Description: 581 bit with an embedding degree of 48 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E'(GF(p^8))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.7 of [[ this specification ]]

## COSE Elliptic Curve Registrations

This section registers the following value in the IANA "JSON Web Key Elliptic Curve" registry [IANA.JOSE.Curves].

Bls12381G1

- Curve Name: Bls12381G1
- Value: 13
- Key Type: OKP
- Curve Description: 381 bit with an embedding degree of 12 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E(GF(p))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.2 of [[ this specification ]]
- Recommended: Yes

Bls12381G2

- Curve Name: Bls12381G2
- Value: 14
- Key Type: OKP
- Curve Description: 381 bit with an embedding degree of 12 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E'(GF(p^2))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.4 of [[ this specification ]]
- Recommended: Yes

Bls48581G1

- Curve Name: Bls48581G1
- Value: 15
- Key Type: OKP
- Curve Description: 581 bit with an embedding degree of 48 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E(GF(p))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.6 of [[ this specification ]]
- Recommended: Yes

Bls48581G2

- Curve Name: Bls48581G2
- Value: 16
- Key Type: OKP
- Curve Description: 581 bit with an embedding degree of 48 Barreto-
Lynn-Scott pairing friendly curve using the r-order subgroup of
E'(GF(p^8))
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 3.8 of [[ this specification ]]
- Recommended: Yes

# Acknowledgments

The authors of this draft would like to acknowledge the pre-work of Kyle Den Hartog which was used as the foundations for this draft.