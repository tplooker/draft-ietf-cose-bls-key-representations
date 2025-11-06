use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use mcore::bls12381;
use mcore::bls48581;
use mcore::hmac::hkdf_expand;
use mcore::hmac::hkdf_extract;
use mcore::hmac::MC_SHA2;
use serde::ser::SerializeMap;
use serde::Serialize;
use serde::Serializer;

const HKDF_KEY: &[u8] = b"Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE";

fn hkdf<const LEN: usize, const BUFLEN: usize>(i: u8, info: &str) -> [u8; BUFLEN] {
    let mut prk = [0; 32];
    hkdf_extract(MC_SHA2, 32, &mut prk, Some(&[i]), HKDF_KEY);
    let mut okm = [0; BUFLEN];
    hkdf_expand(
        MC_SHA2,
        32,
        &mut okm[BUFLEN - LEN..],
        LEN,
        &prk,
        info.as_bytes(),
    );
    okm
}

fn to_hex<T: AsRef<[u8]>>(bytes: T) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn into_new_array<const LEN: usize, F: FnOnce(&mut [u8; LEN]) -> ()>(f: F) -> [u8; LEN] {
    let mut bytes = [0; LEN];
    f(&mut bytes);
    bytes
}

trait Big<const LEN: usize> {
    fn frombytes(bytes: &[u8]) -> Self;
    fn rmod(&mut self, m: &Self);
    fn to_bytes(&self) -> [u8; LEN];
}

impl Big<48> for bls12381::big::BIG {
    fn frombytes(bytes: &[u8]) -> Self {
        Self::frombytes(bytes)
    }
    fn rmod(&mut self, m: &Self) {
        self.rmod(m);
    }
    fn to_bytes(&self) -> [u8; 48] {
        into_new_array(|bytes| self.tobytes(bytes))
    }
}
impl Big<73> for bls48581::big::BIG {
    fn frombytes(bytes: &[u8]) -> Self {
        Self::frombytes(bytes)
    }
    fn rmod(&mut self, m: &Self) {
        self.rmod(m);
    }
    fn to_bytes(&self) -> [u8; 73] {
        into_new_array(|bytes| self.tobytes(bytes))
    }
}

trait ECPExtensions<const COORD_LEN: usize, const PK_LEN: usize> {
    type BIG: Big<COORD_LEN>;
    fn to_bytes(&self) -> [u8; PK_LEN];
    fn generator() -> Self;
    fn mul(&self, scalar: &Self::BIG) -> Self;
    fn order() -> Self::BIG;
}

impl ECPExtensions<48, 48> for bls12381::ecp::ECP {
    type BIG = bls12381::big::BIG;
    fn generator() -> Self {
        Self::generator()
    }
    fn mul(&self, scalar: &Self::BIG) -> Self {
        self.mul(scalar)
    }
    fn order() -> Self::BIG {
        Self::BIG::new_ints(&bls12381::rom::CURVE_ORDER)
    }
    fn to_bytes(&self) -> [u8; 48] {
        into_new_array(|bytes| self.tobytes(bytes, true))
    }
}

impl ECPExtensions<48, 96> for bls12381::ecp2::ECP2 {
    type BIG = bls12381::big::BIG;
    fn generator() -> Self {
        Self::generator()
    }
    fn mul(&self, scalar: &Self::BIG) -> Self {
        self.mul(scalar)
    }
    fn order() -> Self::BIG {
        Self::BIG::new_ints(&bls12381::rom::CURVE_ORDER)
    }
    fn to_bytes(&self) -> [u8; 96] {
        into_new_array(|bytes| self.tobytes(bytes, true))
    }
}

impl ECPExtensions<73, 73> for bls48581::ecp::ECP {
    type BIG = bls48581::big::BIG;
    fn generator() -> Self {
        Self::generator()
    }
    fn mul(&self, scalar: &Self::BIG) -> Self {
        self.mul(scalar)
    }
    fn order() -> Self::BIG {
        Self::BIG::new_ints(&bls48581::rom::CURVE_ORDER)
    }
    fn to_bytes(&self) -> [u8; 73] {
        into_new_array(|bytes| self.tobytes(bytes, true))
    }
}

impl ECPExtensions<73, 584> for bls48581::ecp8::ECP8 {
    type BIG = bls48581::big::BIG;
    fn generator() -> Self {
        Self::generator()
    }
    fn mul(&self, scalar: &Self::BIG) -> Self {
        self.mul(scalar)
    }
    fn order() -> Self::BIG {
        Self::BIG::new_ints(&bls48581::rom::CURVE_ORDER)
    }
    fn to_bytes(&self) -> [u8; 584] {
        into_new_array(|bytes| self.tobytes(bytes, true))
    }
}

struct CoseBlsKey<'d, 'x> {
    crv: i64,
    d: &'d [u8],
    x: &'x [u8],
}

impl<'d, 'x> Serialize for CoseBlsKey<'d, 'x> {
    fn serialize<S>(&self, s: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let mut map = s.serialize_map(Some(4))?;
        map.serialize_entry(&1, &1)?;
        map.serialize_entry(&-1, &self.crv)?;
        map.serialize_entry(&-2, &serde_cbor::value::Value::Bytes(self.x.to_vec()))?;
        map.serialize_entry(&-4, &serde_cbor::value::Value::Bytes(self.d.to_vec()))?;
        map.end()
    }
}

fn wrap_indent(mut s: &str, width: usize, indent: usize) -> String {
    let mut lines: Vec<&str> = Vec::with_capacity(s.len() / width + 1);
    while s.len() > width {
        lines.push(&s[..width]);
        s = &s[width..];
    }
    lines.push(s);
    let sep = format!(
        "\n{}",
        std::iter::repeat(' ').take(indent).collect::<String>()
    );
    lines.join(&sep)
}

fn print_example<
    const SCALAR_LEN: usize,
    const COORD_LEN: usize,
    const PK_LEN: usize,
    ECP: ECPExtensions<COORD_LEN, PK_LEN>,
>(
    crv_name: &str,
    crv_id: i64,
    hkdf_salt: u8,
    format: &str,
) -> Result<(), serde_cbor::Error> {
    let mut dbig = ECP::BIG::frombytes(&hkdf::<SCALAR_LEN, COORD_LEN>(hkdf_salt, crv_name));
    dbig.rmod(&ECP::order());

    let d = &dbig.to_bytes()[COORD_LEN - SCALAR_LEN..];
    let pk = ECP::generator().mul(&dbig);
    let x = pk.to_bytes();

    match format {
        "jwk" => {
            println!(
                r#"
```
{{
  "kty": "OKP",
  "crv": "{crv}",
{x}",
{d}"
}}
```"#,
                crv = crv_name,
                x = wrap_indent(
                    &format!("  \"x\": \"{}", BASE64_URL_SAFE_NO_PAD.encode(&x)),
                    72,
                    0
                ),
                d = wrap_indent(
                    &format!("  \"d\": \"{}", BASE64_URL_SAFE_NO_PAD.encode(d)),
                    72,
                    0
                ),
            );
        }

        "cwk" => {
            println!(
                "```\n{}\n```",
                wrap_indent(
                    &to_hex(&serde_cbor::to_vec(&CoseBlsKey {
                        crv: crv_id,
                        d,
                        x: x.as_slice()
                    })?),
                    72,
                    0
                ),
            );
        }

        "cddl" => {
            println!(
                r#"```
{{
  1 => 1,
  -1 => {crv_id},
  -2 => h'{x}',
  -4 => h'{d}',
}}
```"#,
                crv_id = crv_id,
                x = wrap_indent(&to_hex(x), 64, 10),
                d = wrap_indent(&to_hex(d), 64, 10),
            );
        }

        _ => panic!("Unknown example format: {}", format),
    }

    Ok(())
}

fn main() -> Result<(), serde_cbor::Error> {
    use bls12381::ecp::ECP as BLS12ECP1;
    use bls12381::ecp2::ECP2 as BLS12ECP2;
    use bls48581::ecp::ECP as BLS48ECP1;
    use bls48581::ecp8::ECP8 as BLS48ECP8;
    for arg in std::env::args() {
        if let Some((crv, salt, format)) = arg
            .split_once(':')
            .and_then(|(head, tail)| tail.split_once(':').map(|(h, t)| (head, h, t)))
        {
            if let Ok(salt) = salt.parse::<u8>() {
                match crv {
                    "BLS12381G1" => print_example::<32, 48, 48, BLS12ECP1>(crv, 13, salt, format)?,
                    "BLS12381G2" => print_example::<32, 48, 96, BLS12ECP2>(crv, 13, salt, format)?,
                    "BLS48581G1" => print_example::<65, 73, 73, BLS48ECP1>(crv, 14, salt, format)?,
                    "BLS48581G2" => print_example::<65, 73, 584, BLS48ECP8>(crv, 14, salt, format)?,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::DecodeError;

    #[test]
    fn test_bls12381g1_generator() -> Result<(), DecodeError> {
        const EXPECT_X: &str = "l_HTpzGX15QmlWOMT6msD8NojE-XdLkFoU46PxcbrFhsVeg_-Xoa7_s68ArbIsa7";
        let g = bls12381::ecp::ECP::generator();
        assert_eq!(
            &g.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(g.to_bytes()), EXPECT_X);
        Ok(())
    }

    #[test]
    fn test_bls12381g1_generator_mul_2() -> Result<(), DecodeError> {
        const EXPECT_X: &str = "pXLL6pBNZ0aICMjrUKlFDJch2zCRKAElQ5AtCsNYpirij3W7jxx8QsOajFUpvw9O";
        let g = bls12381::ecp::ECP::generator().mul(&bls12381::big::BIG::new_int(2));
        assert_eq!(
            &g.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(g.to_bytes()), EXPECT_X);
        Ok(())
    }

    #[test]
    fn test_bls12381g2_generator() -> Result<(), DecodeError> {
        const EXPECT_X: &str = "k-ArYFJxn2B9rNOgiCdPZVlr0NCZILYatdphu9x_UEkzTPESE5RdV-WsfQVdBCt-AkqisvCPCpEmCAUnLcUQUcbketT6QDsCtFELZHrj0XcLrAMmqAW779SAVsjBIb24";
        let g = bls12381::ecp2::ECP2::generator();
        assert_eq!(
            &g.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(g.to_bytes()), EXPECT_X);
        Ok(())
    }

    #[test]
    fn test_bls12381g2_generator_mul_2() -> Result<(), DecodeError> {
        const EXPECT_X: &str = "qk7e-cHtf3KfUg5HcwoST9cGYqkEuhB0coEU0QMeFXLGyIb2tX7HKmF4KIxHwzV3FjhTOVfVQKnSNw8XzH7VhjvAuZW4gl4O4eoeHk0A266B8UsL82EbeMlSqsq4J6BT";
        let g = bls12381::ecp2::ECP2::generator().mul(&bls12381::big::BIG::new_int(2));
        assert_eq!(
            &g.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(g.to_bytes()), EXPECT_X);
        Ok(())
    }

    #[test]
    fn test_bls12381g2_known_1() -> Result<(), DecodeError> {
        const D: &str = "IgRY0ektXHs-heJjAsVTRaMI6OL3W_kYuzGaid2yeQ4";
        const EXPECT_X: &str = "t2IMOefTklK0-lLsfbbnHeik-ax-x-aZVTcXe9heYDme1PhsyDtUzivz-oTg-ZDJDnmbAW1GJwN65w3I0U7q-PgauHW8RoGzc_l7Ac2QBDyKhbfaQ_X0DhqtkAwxXiC2";
        let d = bls12381::big::BIG::frombytes(&{
            let mut v = BASE64_URL_SAFE_NO_PAD.decode(D)?;
            for _ in 0..16 {
                v.insert(0, 0);
            }
            v
        });
        let x = bls12381::ecp2::ECP2::generator().mul(&d);
        assert_eq!(
            &x.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(x.to_bytes()), EXPECT_X);
        Ok(())
    }

    #[test]
    fn test_bls12381g2_known_2() -> Result<(), DecodeError> {
        const D: &str = "O4x7NVtBvaLb-SZxGe3CKzl7obmSD47aLmReKdKQ_v8";
        const EXPECT_X: &str = "rgPyS3U6AR_cOuRC1LSxNmw5HfLlAurrRdFGjwyrZihZyeIoqMXQhr7aGM0eo1iSE2WGstFUjZShhfoF2mK1D61CXFyOAoM-Qt6e7NZjsN9LKZNpGNHnFttuMrlBvk6v";
        let d = bls12381::big::BIG::frombytes(&{
            let mut v = BASE64_URL_SAFE_NO_PAD.decode(D)?;
            for _ in 0..16 {
                v.insert(0, 0);
            }
            v
        });
        let x = bls12381::ecp2::ECP2::generator().mul(&d);
        assert_eq!(
            &x.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(x.to_bytes()), EXPECT_X);
        Ok(())
    }

    #[test]
    fn test_bls12381g2_known_3() -> Result<(), DecodeError> {
        const D: &str = "OmOoDblLqB-yg4pz4f_n-zkKAZW-YoWOXqiytTQwFRg";
        const EXPECT_X: &str = "pZYn75C9zJpSj-mEIjCusDncS5xmJFpc3ZSx2IjG4V4fGCRc1O8TfTHUstHqNQacE4iPMbyyh97xG3DUn1eH_ViDkrSFvcgOXlx-iyO1UU9b_W43Em7WzwoIpoCYIpCb";
        let d = bls12381::big::BIG::frombytes(&{
            let mut v = BASE64_URL_SAFE_NO_PAD.decode(D)?;
            for _ in 0..16 {
                v.insert(0, 0);
            }
            v
        });
        let x = bls12381::ecp2::ECP2::generator().mul(&d);
        assert_eq!(
            &x.to_bytes(),
            BASE64_URL_SAFE_NO_PAD.decode(EXPECT_X)?.as_slice(),
        );
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(x.to_bytes()), EXPECT_X);
        Ok(())
    }
}
