//!   Message types used by MPC algorithms in the crate
//!
#![allow(non_snake_case)]
#![allow(clippy::large_enum_variant)]

use crate::types::CurvVerifiableSS;
use crate::types::{BigInt, FE, GE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// key generation related message data types
pub mod keygen {
    use super::{BigInt, GE};
    use crate::keygen::CorrectKeyProof;
    use crate::messages::FeldmanVSS;
    use crate::zk_range_proofs::ZkpPublicSetup;

    use crate::types::CurvDLogProofType;
    use paillier::EncryptionKey;
    use serde::{Deserialize, Serialize};

    /// Enumerates messages used by key generation algorithm
    #[derive(Debug, Clone, Deserialize, Serialize, Display)]
    pub enum Message {
        R1(Phase1Broadcast),
        R2(DecommitPublicKey),
        R3(FeldmanVSS),
        R4(CurvDLogProofType),
    }

    pub type InMsg = crate::protocol::InputMessage<Message>;
    pub type OutMsg = crate::protocol::OutputMessage<Message>;

    impl InMsg {
        pub fn is_duplicate(&self, current_msg_set: &[InMsg]) -> bool {
            current_msg_set.iter().any(|m| m.sender == self.sender)
        }
    }

    // Conversion helpers : unwrap MessageType variant to one of its inner structs
    impl From<Message> for Option<Phase1Broadcast> {
        fn from(x: Message) -> Option<Phase1Broadcast> {
            match x {
                Message::R1(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<DecommitPublicKey> {
        fn from(m: Message) -> Option<DecommitPublicKey> {
            match m {
                Message::R2(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<FeldmanVSS> {
        fn from(m: Message) -> Option<FeldmanVSS> {
            match m {
                Message::R3(fvss) => Some(fvss),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<CurvDLogProofType> {
        fn from(m: Message) -> Option<CurvDLogProofType> {
            match m {
                Message::R4(proof) => Some(proof),
                _ => None,
            }
        }
    }

    /// Initial broadcast in the key generation protocol
    ///
    /// Contains:
    /// * public Paillier key
    /// * commitment to partial public EC schema key
    /// * proof for Paillier key
    /// * optional public range proof setup   
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Phase1Broadcast {
        pub e: EncryptionKey,
        pub com: BigInt,
        pub correct_key_proof: CorrectKeyProof,
        pub range_proof_setup: Option<ZkpPublicSetup>,
    }

    /// Decommitment of partial public EC schema key
    #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    pub struct DecommitPublicKey {
        pub blind_factor: BigInt,
        pub y_i: GE,
    }
}

/// Message data types used by the signing algorithm
pub mod signing {
    use super::{BigInt, FE, GE};
    use crate::zk_range_proofs::{MessageA, MessageB};

    use crate::types::{CurvDLogProofType, CurvHomoElGamalProof};
    use serde::{Deserialize, Serialize};

    pub type InMsg = crate::protocol::InputMessage<Message>;
    pub type OutMsg = crate::protocol::OutputMessage<Message>;

    /// Initial broadcast of the signing protocol
    ///
    /// Contains commitment to $` g^{\gamma_{i}} `$ and the first message ( `MessageA` )  of `MtA` protocol
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignBroadcastPhase1 {
        pub com: BigInt,
        pub mta_a: MessageA,
    }

    /// Decommitment of $` g^{\gamma_{i}} `$ and ZKP of knowing $` \gamma_{i} `$.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignDecommitPhase4 {
        pub blind_factor: BigInt,
        pub g_gamma_i: GE,
        pub gamma_proof: CurvDLogProofType,
    }

    /// Commitment to $` V_{i} , \space A_{i} `$, see `Phase5A` in the paper
    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Phase5Com1 {
        pub com: BigInt,
    }

    /// Commitment to $` U_{i}, \space T_{i} `$, see `Phase5C` in the paper
    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Phase5Com2 {
        pub com: BigInt,
    }

    /// Decommitment to $` V_{i} , \space A_{i} `$ and ZKP of it, see Phase 5B in the paper
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Phase5Decom1 {
        pub V_i: GE,
        pub A_i: GE,
        pub B_i: GE,
        pub blind_factor: BigInt,
        pub proof: CurvHomoElGamalProof,
    }

    /// Decommitment to $` U_{i} , \space T_{i} `$, see Phase 5D in the paper
    #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    pub struct Phase5Decom2 {
        pub U_i: GE,
        pub T_i: GE,
        pub blind_factor: BigInt,
    }

    /// the broadcast of $` \delta_{i} `$, see `Phase3` in the paper
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Phase3data {
        pub delta_i: FE,
    }

    /// the final broadcast of the signing protocol, partial signature $` \s_{i} `$, see `Phase5E`
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Phase5Edata {
        pub s_i: FE,
    }

    /// Messages used by signing algorithm
    #[derive(Debug, Clone, Deserialize, Serialize, Display)]
    pub enum Message {
        R1(SignBroadcastPhase1),
        R2(MessageB),
        R2b(MessageB),
        R3(Phase3data),
        R4(SignDecommitPhase4),
        R5(Phase5Com1),
        R6(Phase5Decom1),
        R7(Phase5Com2),
        R8(Phase5Decom2),
        R9(Phase5Edata), // signature part
    }

    impl InMsg {
        pub fn is_duplicate(&self, current_msg_set: &[InMsg]) -> bool {
            current_msg_set.iter().any(|m| m.sender == self.sender)
        }
    }

    // Conversion helpers : unwrap MessageType variant to one of its inner structs
    impl From<Message> for Option<SignBroadcastPhase1> {
        fn from(x: Message) -> Option<SignBroadcastPhase1> {
            match x {
                Message::R1(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<SignDecommitPhase4> {
        fn from(x: Message) -> Option<SignDecommitPhase4> {
            match x {
                Message::R4(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<MessageB> {
        fn from(x: Message) -> Option<MessageB> {
            match x {
                Message::R2(msg) | Message::R2b(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase3data> {
        fn from(x: Message) -> Option<Phase3data> {
            match x {
                Message::R3(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase5Com1> {
        fn from(x: Message) -> Option<Phase5Com1> {
            match x {
                Message::R5(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase5Decom1> {
        fn from(x: Message) -> Option<Phase5Decom1> {
            match x {
                Message::R6(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase5Com2> {
        fn from(x: Message) -> Option<Phase5Com2> {
            match x {
                Message::R7(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase5Decom2> {
        fn from(x: Message) -> Option<Phase5Decom2> {
            match x {
                Message::R8(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase5Edata> {
        fn from(x: Message) -> Option<Phase5Edata> {
            match x {
                Message::R9(msg) => Some(msg),
                _ => None,
            }
        }
    }
}
/// key resharing related message data types
pub mod resharing {
    use crate::keygen::CorrectKeyProof;
    use crate::messages::SecretShare;
    use crate::zk_range_proofs::ZkpPublicSetup;

    use crate::types::BigInt;

    use crate::types::{CurvVerifiableSS, GE};
    use paillier::EncryptionKey;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Phase1Broadcast {
        pub y: GE,
        pub vss_commitment: BigInt,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Phase2Broadcast {
        pub ek: EncryptionKey,
        pub correct_key_proof: CorrectKeyProof,
        pub range_proof_setup: Option<ZkpPublicSetup>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VSS {
        pub share: SecretShare,
        pub vss: CurvVerifiableSS,
    }

    /// Messages used by key resharing algorithm
    #[derive(Debug, Clone, Deserialize, Serialize, Display)]
    pub enum Message {
        R1(Phase1Broadcast),
        R2(Phase2Broadcast),
        R3(VSS),
        Ack,
        FinalAck,
    }

    pub type InMsg = crate::protocol::InputMessage<Message>;
    pub type OutMsg = crate::protocol::OutputMessage<Message>;

    impl InMsg {
        pub fn is_duplicate(&self, current_msg_set: &[InMsg]) -> bool {
            current_msg_set.iter().any(|m| m.sender == self.sender)
        }
    }

    // Conversion helpers : unwrap MessageType variant to one of its inner structs
    impl From<Message> for Option<Phase1Broadcast> {
        fn from(x: Message) -> Option<Phase1Broadcast> {
            match x {
                Message::R1(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<Phase2Broadcast> {
        fn from(x: Message) -> Option<Phase2Broadcast> {
            match x {
                Message::R2(msg) => Some(msg),
                _ => None,
            }
        }
    }

    impl From<Message> for Option<VSS> {
        fn from(x: Message) -> Option<VSS> {
            match x {
                Message::R3(msg) => Some(msg),
                _ => None,
            }
        }
    }
}

/// Shamir's secret share
///
/// Contains x and y-coordinate of the point
pub type SecretShare = (u16, FE);

/// The message by which the Shamir's secret share and its verifiable proof is shared with a counterparty
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeldmanVSS {
    pub vss: CurvVerifiableSS,
    pub share: SecretShare,
}

impl Zeroize for FeldmanVSS {
    fn zeroize(&mut self) {
        self.vss.parameters.threshold.zeroize();
        self.vss.parameters.share_count.zeroize();
        self.vss
            .commitments
            .drain(..)
            .for_each(|c| c.into_raw().zeroize());

        // TODO: zeroize
        //self.share.0.zeroize();
        //self.share.1.into_raw().underlying_ref().zeroize();
    }
}

impl Drop for FeldmanVSS {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FeldmanVSS {
    pub fn verify(&self, pubkey: &GE) -> bool {
        let valid = self.vss.validate_share(&self.share.1, self.share.0).is_ok();
        let pubkey_valid = self.vss.commitments[0] == *pubkey;
        if valid && pubkey_valid {
            log::debug!("validated FVSS {:?}\n", &self);
        } else {
            if !valid {
                log::error!("failed FVSS {:?}\n", &self);
            }
            if !pubkey_valid {
                log::error!("invalid pubkey in FVSS {:?}\n", &self);
            }
        }
        valid && pubkey_valid
    }
}
