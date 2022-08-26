pub(crate) use curv::arithmetic::traits::Converter;

#[allow(unused_imports)]
pub(crate) use curv::arithmetic::{BigInt, Integer, One, Samplable, Zero};

use crate::keygen::KeygenError;
use crate::protocol::PartyIndex;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
pub use curv::elliptic::curves::Secp256k1;

pub type Point = curv::elliptic::curves::Point<Secp256k1>;
pub type Scalar = curv::elliptic::curves::Scalar<Secp256k1>;
pub(crate) type GE = Point;
pub(crate) type FE = Scalar;

pub(crate) use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
pub(crate) type CurvDLogProofType = DLogProof<Secp256k1, sha2::Sha256>;

pub type SecretShares =
    curv::cryptographic_primitives::secret_sharing::feldman_vss::SecretShares<Secp256k1>;

pub(crate) use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
pub(crate) type CurvVerifiableSS = VerifiableSS<Secp256k1>;

pub(crate) use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::{
    HomoELGamalProof, HomoElGamalStatement, HomoElGamalWitness,
};
pub(crate) type CurvHomoElGamalProof = HomoELGamalProof<Secp256k1, sha2::Sha256>;

pub(crate) use curv::cryptographic_primitives::hashing::DigestExt;

use crate::utils::is_valid_curve_point;
pub(crate) use curv::elliptic::curves::PointFromBytesError;

use paillier::EncryptionKey;

pub(crate) use algorithms::types::PaillierKeys;
use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

pub use trace::trace;

/// Parameters associated with shared key in threshold schema
///
/// # Key Attributes
///
/// * `share count` - number of parties which hold shards of the key
/// * `threshold` - number of parties required to produce a signature minus 1 so that $` \min N_{required} = threshold + 1 `$
#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct Parameters {
    threshold: u16,   //t
    share_count: u16, //n
}

impl Parameters {
    /// Constructs new Parameters conditioned they satisfy `2 <= min_signers <= share_count`.
    ///
    /// Parameters are used for Shamir secret sharing, so that the threshold sharing parameter
    /// is equal to the degree of the polynomial used in sharing.
    ///
    /// That is, `threshold` = `min_signers` - 1
    /// Refer to <https://eprint.iacr.org/2019/114.pdf>
    pub fn new(min_signers: u16, share_count: u16) -> Result<Self, KeygenError> {
        if share_count < 2 {
            return Err(KeygenError::IncorrectParameters(format!(
                "Number of shares must be at least 2, got {}",
                share_count
            )));
        }
        // share_count >= 2

        if min_signers < 2 {
            return Err(KeygenError::IncorrectParameters(format!(
                "Number of signers must be at least 2, got: {}",
                min_signers
            )));
        }
        // min_signers >= 2

        if min_signers > share_count {
            return Err(KeygenError::IncorrectParameters(format!(
                "Number of signers {} cannot be greater than number of shares {}",
                min_signers, share_count
            )));
        }

        //
        // 1 <= min_signers - 1 = threshold < share_count

        Ok(Parameters {
            threshold: min_signers - 1,
            share_count,
        })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn share_count(&self) -> u16 {
        self.share_count
    }

    pub fn signers(&self) -> u16 {
        self.threshold + 1
    }
}

impl fmt::Display for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{threshold: {}, share_count: {}}}",
            self.threshold, self.share_count
        )
    }
}

pub type MessageHashType = FE;

///  Initial values for signing algorithm
///
///  The signing algorithm starts knowing `PartyIndexes` of participants and the hash of the message
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigningParameters {
    pub keygen_params: Parameters,
    pub signing_parties: BTreeSet<PartyIndex>,
    pub message_hash: MessageHashType,
}

impl SigningParameters {
    pub fn signing_party_count(&self) -> usize {
        self.signing_parties.len()
    }
}

/// Public/private key pairs used by a party during key generation for one given shared key
///
/// Public/private key pair `u_i,y_i` for the EC schema, and Public/private `paillier_keys` for homomorphic encryption schema.
///
/// Note that EC schema keys $` u_{i}, y_{i} `$ become obsolete after the round of Shamir's sharing so that they have to be erased.
/// Unlike these keys, Paillier keys will be used later in the signing protocol, therefore if the struct `InitialKeys` is about to be dropped or erased explicitly, Paillier keys must be copied to another location beforehand.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitialKeys {
    pub u_i: FE,
    pub y_i: GE,
    pub paillier_keys: PaillierKeys,
}

impl Display for InitialKeys {
    /// hides private key `u_i`
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialKeys")
            .field("u_i", &"[***]".to_owned())
            .field("y_i", &self.y_i)
            .field("paillier keys", &self.paillier_keys)
            .finish()
    }
}

impl Debug for InitialKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// Truncated version of `InitialKeys`, without secret part of each key
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InitialPublicKeys {
    pub y_i: GE,
    pub paillier_encryption_key: EncryptionKey,
}

impl InitialPublicKeys {
    pub fn from(keys: &InitialKeys) -> Self {
        Self {
            y_i: keys.y_i.clone(),
            paillier_encryption_key: keys.paillier_keys.ek.clone(),
        }
    }
}

/// The result of ECDSA signing algorithm
///
/// The signature the schema with
///
/// * cyclic group $` \mathcal{G} `$ of prime order $`q`$ and generator $` g `$
/// * message $` m `$ , private key $` x `$
/// * mapping $` F : \mathcal{G} \to \mathbb{Z}_q `$, hash function $` H(t) `$
/// * random  $` k \in \mathbb{Z}_{q} `$
///
/// The signature contains
/// ```math
///    r = F(g^k) , \space s = k^{-1}(H(m) + x r) \mod q
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: FE,
    pub s: FE,
}

impl Signature {
    /// verifies the signature using public key and the hash of the message
    pub fn verify(&self, pubkey: &GE, message: &MessageHashType) -> bool {
        if self.s == FE::zero() || self.r == FE::zero() {
            false
        } else {
            let g = GE::generator();

            let s_invert = self.s.invert().unwrap();
            let u1 = message * &s_invert;
            let u2 = &self.r * s_invert;

            self.r
                == Scalar::from(
                    &(g * u1 + pubkey * &u2)
                        .x_coord()
                        .unwrap()
                        .mod_floor(FE::group_order()),
                )
        }
    }
}

///  Non-malleable commitment scheme
///
/// Commitment scheme based on hash commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitmentScheme {
    pub comm: BigInt,
    pub decomm: BigInt,
}

impl CommitmentScheme {
    /// creates commitment scheme from EC group element
    #[allow(non_snake_case)]
    pub fn from_GE(elem: &GE) -> Self {
        let decomm = BigInt::sample(256);
        let comm = HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&elem.to_bytes(true)),
            &decomm,
        );
        CommitmentScheme { comm, decomm }
    }

    /// creates commitment scheme from `BigInt`
    #[allow(non_snake_case)]
    pub fn from_BigInt(message: &BigInt) -> Self {
        let decomm = BigInt::sample(256);
        let comm = HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            message, &decomm,
        );
        CommitmentScheme { comm, decomm }
    }

    /// verifies commitment using EC group element
    pub fn verify_commitment(&self, elem: &GE) -> bool {
        is_valid_curve_point(elem)
            && HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(&elem.to_bytes(true)),
                &self.decomm,
            ) == self.comm
    }

    /// verifies commitment using `BigInt` value
    pub fn verify_hash(&self, hash: &BigInt) -> bool {
        HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            hash,
            &self.decomm,
        ) == self.comm
    }
}
