use crate::config::PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA;
pub use curv::arithmetic::traits::{BasicOps, BitManipulation, Converter, NumberTests};
pub use curv::arithmetic::{BigInt, Integer, Modulo, One, Samplable, Zero};
pub use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
pub use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};

#[allow(dead_code)]
pub(crate) type Scalar = curv::elliptic::curves::Scalar<curv::elliptic::curves::Secp256k1>;

use std::borrow::Borrow;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::sync::atomic;
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use trace::trace;

/// Public/private key pair for additive homomorphic encryption schema
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PaillierKeys {
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
}

impl Zeroize for PaillierKeys {
    fn zeroize(&mut self) {
        self.dk.p.zeroize();
        self.dk.q.zeroize();
        self.ek.n.zeroize();
        self.ek.nn.zeroize();
    }
}

impl Drop for PaillierKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PaillierKeys {
    /// initializes with zeros
    pub fn zero() -> Self {
        Self {
            dk: DecryptionKey {
                p: BigInt::zero(),
                q: BigInt::zero(),
            },
            ek: EncryptionKey {
                n: BigInt::zero(),
                nn: BigInt::zero(),
            },
        }
    }

    /// produces new Paiiliier key pair
    pub fn random() -> Self {
        let (ek, dk) =
            Paillier::keypair_with_modulus_size(2 * PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA).keys();
        Self { ek, dk }
    }

    /// decrypts given value `c`
    pub fn decrypt(&self, c: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(c))
    }

    /// checks whether Paillier's setup is valid and consistent
    #[trace(pretty, prefix = "PaillierKeys::")]
    pub fn is_valid(ek: &EncryptionKey, dk: &DecryptionKey) -> bool {
        use paillier::is_prime;
        // TODO : report back specific errors
        is_prime(&dk.p)
            && is_prime(&dk.q)
            && ek.n == dk.p.borrow() * dk.q.borrow()
            && ek.nn == ek.n.pow(2)
    }
}

impl Display for PaillierKeys {
    /// hides private key of the schema
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaillierKeys")
            .field("dk", &"[***]".to_owned())
            .field("ek", &self.ek)
            .finish()
    }
}

impl Debug for PaillierKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub struct ManagedPaillierDecryptionKey(pub Box<DecryptionKey>);

impl Drop for ManagedPaillierDecryptionKey {
    fn drop(&mut self) {
        self.0.p = BigInt::zero();
        self.0.q = BigInt::zero();
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

//use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
//

pub trait Powm
where
    Self: Sized,
{
    #![allow(clippy::needless_arbitrary_self_type)]
    fn powm_sec(self: &Self, exponent: &Self, modulus: &Self) -> Self;
}

// this is quick & dirty fix:
// the underlying GMP call is NOT powm_sec(),
// and inner object is private
impl Powm for BigInt {
    #![allow(clippy::needless_arbitrary_self_type)]
    fn powm_sec(self: &Self, exponent: &Self, modulus: &Self) -> Self {
        assert!(exponent >= &BigInt::zero(), "exponent must be non-negative");
        BigInt::mod_pow(self, exponent, modulus)
    }
}
