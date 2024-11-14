use peqpreimage_snark::{DefaultCommitandProvePeqScheme, DefaultIvcPeqScheme, PeqSnark, Serialize};
use sha2::Digest;

/// Implementation of [TransactionRedactionSnark][crate::TransactionRedactionSnark] with Groth16 via 
/// a commit-and-prove approach. This implementation produces as many proofs as SHA256 blocks 
/// in the preimage.
pub type DefaultCommitandProveTxredactionScheme = DefaultCommitandProvePeqScheme;


/// Implementation of [TransactionRedactionSnark][crate::TransactionRedactionSnark] with Nova, an IVC scheme. 
/// This implementation produces a single proof.
pub type DefaultIvcTxredactionScheme = DefaultIvcPeqScheme;


/// The SNARK to prove and verify correct partial redaction on transaction bytes.
/// 
/// Partial equality of original and redacted transactions is done at the byte level.
pub trait TransactionRedactionSnark {
    type ProverKey;
    type VerifierKey;
    type Proof;

    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)>;

    fn prove(
        pk: &Self::ProverKey, 
        redacted_tx_bytes: &[u8],
        selector: &[bool],
        mined_txid: &[u8],
        original_tx_bytes: &[u8] 
    ) -> Option<Self::Proof>;

    fn verify(
        vk: &Self::VerifierKey,
        redacted_tx_bytes: &[u8],
        selector: &[bool],
        mined_txid: &[u8],
        proof: &Self::Proof
    ) -> Option<bool>;
}

/// A proof of a [TransactionRedactionSnark] contains the byte digest of the 
/// original transaction. Thus, the proof `leaks' the original digest.
// This saves some constraints at proof generation.
pub struct LeakingProof<S:PeqSnark> {
    peq_proof: <S as PeqSnark>::Proof,
    original_digest: sha256_cf::Digest
}

impl<S:PeqSnark> LeakingProof<S> {
    
    pub fn new(peq_proof: <S as PeqSnark>::Proof,original_digest: &[u8]) -> Self {
        
        assert_eq!(original_digest.len(),32, "Invalid SHA256 digest size");
        let original_digest: sha256_cf::State = original_digest.to_vec().try_into().unwrap();
        
        LeakingProof {
            peq_proof, 
            original_digest: original_digest.into()
        }
    }

    /// Returns the original digest embeded in this proof.
    fn leak_digest(&self) -> sha256_cf::Digest {
        self.original_digest
    }

    /// Computes the txid from the inner digest of this proof and checks against the mined txid. 
    /// (The input `mined_txid` is the correct one because it has PoW.)
    fn original_digest_is_correct(&self, mined_txid: [u8;32] ) -> bool {
        
        let correct_txid = sha2::Sha256::digest(&self.original_digest.to_be_bytes());

        mined_txid == correct_txid.as_slice()
    }

    pub fn serialized_proof_size(&self) -> usize {
        self.peq_proof.serialized_size()
    }
}

/// This blanket implementation just adds the extra logic for consistency 
/// between the original digest and the mined txid.
impl<S:PeqSnark> TransactionRedactionSnark for S {
    type ProverKey = <S as PeqSnark>::ProverKey;

    type VerifierKey = <S as PeqSnark>::VerifierKey;

    type Proof = LeakingProof<S>;

    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)> {
        <S as PeqSnark>::setup()
    }

    fn prove(
        pk: &Self::ProverKey, 
        redacted_tx_bytes: &[u8],
        selector: &[bool],
        mined_txid: &[u8],
        original_tx_bytes: &[u8] 
    ) -> Option<Self::Proof> {

        assert_eq!(mined_txid.len(),32," Incorrect txid length");
        let mined_txid_arr:[u8;32] = mined_txid.try_into().unwrap();
        
        let original_digest = sha2::Sha256::digest(original_tx_bytes);

        let peq_proof = <S as PeqSnark>::prove(
            pk, 
            redacted_tx_bytes, 
            selector, 
            &original_digest, 
            original_tx_bytes)
        .unwrap();

        let txredaction_proof = LeakingProof::<S>::new(peq_proof, &original_digest);
        assert!(txredaction_proof.original_digest_is_correct(mined_txid_arr));

        Some(txredaction_proof)
    }

    fn verify(
        vk: &Self::VerifierKey,
        redacted_tx_bytes: &[u8],
        selector: &[bool],
        mined_txid: &[u8],
        proof: &Self::Proof
    ) -> Option<bool> {
        
        if mined_txid.len() != 32 
        { 
            return Some(false)
        }
        let mined_txid_arr:[u8;32] = mined_txid.try_into().unwrap();

        if !proof.original_digest_is_correct(mined_txid_arr) 
        {
            return Some(false)
        }

        <S as PeqSnark>::verify(
            vk,
            redacted_tx_bytes, 
            selector, 
            &proof.leak_digest().to_be_bytes(), 
            &proof.peq_proof)
    }
}

