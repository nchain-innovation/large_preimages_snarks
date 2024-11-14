//! Implementations of [PeqSnark][crate::PeqSnark] via the commit-and-prove approach.

pub mod circuit;
pub mod groth16;
pub mod pedersen;

use circuit::{MidPrivateInput, MidPublicInput};
use pedersen::{PedersenCommitment, PedersenCommitmentScheme, PedersenKey, PedersenRandomness};
use sha256_cf::State;

use crate::{PeqSnark, PrepareCircuits, Serialize};

use self::circuit::MidCircuit;

use ark_serialize::*;

use rayon::prelude::*;

/// The curve BLS12-381 over which we instantiate [`Groth16`][groth16::Groth16MidPeqJubJub].
type BLS12 = ark_bls12_381::Bls12_381;

/// JubJub is a twisted Edward curve whose base field is set to the scalar field of [BLS12].
/// This means we can prove preimage knowledge of Pedersen hashes (over JubJub) 
/// using a paring-based SNARK over BLS-12-381, such as [`Groth16`][groth16::Groth16bls].
type JubJub = ark_ec::models::twisted_edwards::Projective<ark_ed_on_bls12_381::JubjubConfig>;

/// The base field of [JubJub] is the finite field over which we define the [`MidCircuit`][circuit::MidCircuit].
pub(crate) type JubJubBaseField =ark_ed_on_bls12_381::Fq;

/// A trait specifying a SNARK for the [MidCircuit].
pub trait CpSnark 
{
    type ProverKey: Send + Sync + CpSnarkKey;
    type VerifierKey: Sync + CpSnarkKey;
    type Proof: Send + Clone + CanonicalSerialize;

    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)>;

    fn prove(
        pk: &Self::ProverKey, 
        pub_inp: MidPublicInput,
        priv_inp: MidPrivateInput
        ) -> Option<Self::Proof>;
    fn verify(
        vk: &Self::VerifierKey,
        pub_inp: &MidPublicInput,
        proof: &Self::Proof
    ) -> Option<bool>;
}

/// Returns the commitment key generated at setup of the
/// [MidSNARK] and embedded in the prover/verifier key.
pub trait CpSnarkKey {
    fn commitment_key(&self) -> PedersenKey;
}

impl<PK:CpSnarkKey> PrepareCircuits<MidCircuit> for PK {

    fn instantiate_prover_circuits(
        &self,
        original_bytes: &[u8],
        redacted_bytes: &[u8],
        selector: &[bool]
    ) -> Vec<MidCircuit> {

        assert_eq!(redacted_bytes.len(),original_bytes.len());
        assert_eq!(original_bytes.len(),selector.len());

        let commitment_key = self.commitment_key();

        // Pad and compute blocks for original and redacted bytes and selector bits
        let (original_blocks,_) = crate::Padder::pad_block_and_selector(original_bytes, selector);
        let (redacted_blocks,sel_blocks) = crate::Padder::pad_block_and_selector(redacted_bytes, selector);
        
        // Compute SHA-256 midstates and their commitments
        let iv = sha256_cf::Sha256CF::get_iv();
        let mut midstates = Vec::new();
        let mut commitments:Vec<PedersenCommitment> = Vec::new();
        let mut randomness: Vec<PedersenRandomness> = Vec::new();
        
        let rnd = PedersenRandomness::random_element();
        let commitment_iv = PedersenCommitmentScheme::commit(
            &commitment_key, 
            &iv, 
            &rnd)
            .unwrap();
        midstates.push(iv);
        commitments.push(commitment_iv);
        randomness.push(rnd);

        let mut cur_mid = iv;
        let mut new_mid: State = [0u32;8].into(); // Dummy assign.
        for block in original_blocks.iter() {
            new_mid = sha256_cf::Sha256CF::apply_compression_function(&cur_mid,block);
            midstates.push(new_mid);
            
            let rnd = PedersenRandomness::random_element();
            let commitment = PedersenCommitmentScheme::commit(&commitment_key, &new_mid, &rnd).unwrap();
            commitments.push(commitment);
            randomness.push(rnd);
            
            cur_mid = new_mid;
        }        
        // Sanity check
        assert_eq!(original_blocks.len(),redacted_blocks.len());
        assert_eq!(original_blocks.len(),sel_blocks.len());
        assert_eq!(original_blocks.len()+1,midstates.len());
        assert_eq!(original_blocks.len()+1,commitments.len());
        assert_eq!(original_blocks.len()+1,randomness.len());

        // Create circuits
        let mut circuits:Vec<MidCircuit> = Vec::new();
        for i in 0..original_blocks.len() {
            
            let public_input = MidPublicInput::new_public_input(
                &redacted_blocks[i], 
                &sel_blocks[i], 
                &commitments[i+1], 
                &commitments[i]);

            let private_input = MidPrivateInput::new_private_input(
                &original_blocks[i],
                &midstates[i+1], 
                &midstates[i], 
                &randomness[i+1], 
                &randomness[i]);
        
            circuits.push(MidCircuit::new(&public_input,&private_input,&commitment_key));
        }
        circuits
    }
}

#[derive(CanonicalSerialize,Clone)]
pub struct CpProofs<T : CpSnark> {
    pub midpeq_proofs: Vec<<T as CpSnark>::Proof>,
    /// The commitments to the midstates.
    pub commitments: Vec<PedersenCommitment>,
    /// The randommness used to commit `original_digest` 
    /// in the commitment.
    pub randomness_original_digest: PedersenRandomness,
}

impl<T:CpSnark> Serialize for CpProofs<T> {
    
    fn serialized_size(&self) -> usize {

        <CpProofs<T> as CanonicalSerialize>
        ::serialized_size(self,ark_serialize::Compress::Yes)
    }
}

/// This blanket implementation generates and verifies proofs in parallel 
/// for several instances of `MidCircuit`s.
impl<T:CpSnark+Clone> PeqSnark for T {
    type ProverKey = <T as CpSnark>::ProverKey;
    type VerifierKey = <T as CpSnark>::VerifierKey;
    type Proof = CpProofs<T>;
    
    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)> {
        <T as CpSnark>::setup()
    }
    
    fn prove(
        pk: &Self::ProverKey, 
        redacted_bytes: &[u8],
        selector: &[bool],
        original_digest: &[u8],
        original_bytes: &[u8] 
    ) -> Option<Self::Proof> {
        
        let circuits = pk.instantiate_prover_circuits(original_bytes, redacted_bytes, selector);
            
        // Prove satisfiability of all circuits in parallel.
        let proofs_opt:Vec<Option<<T as CpSnark>::Proof>> = circuits.clone().into_par_iter()
        .map(
            |circuit| T::prove(
                    pk,
                     circuit.public_input, 
                     circuit.private_input)
        )
        .collect();

        let mut midpeq_proofs: Vec<<T as CpSnark>::Proof>= Vec::new();
        for option in proofs_opt {
            midpeq_proofs.push(option?);
        }

        // Move all mid commitments, original bytes digest, and its randomness
        // from public inputs to final proof.
        let mut commitments: Vec<PedersenCommitment> = Vec::new();
        for circuit in circuits.iter() {
            commitments.push(circuit.public_input.previous_state_commitment());
        }
        let last_circuit = circuits.last()?;
        commitments.push(last_circuit.public_input.current_state_commitment());
        
        // Sanity check
        assert_eq!(original_digest.len(),32, "Invalid digest length");
        assert_eq!(original_digest,last_circuit.private_input.current_state().to_be_bytes(), "Input digest is invalid for the input bytes");

        Some(CpProofs::<T>{
                midpeq_proofs,
                commitments,
                randomness_original_digest: last_circuit.private_input.current_randomness()
        })
    }
    
    fn verify(
        vk: &Self::VerifierKey,
        redacted_bytes: &[u8],
        selector: &[bool],
        original_digest: &[u8],
        proof: &Self::Proof
    ) -> Option<bool> {

        if original_digest.len() != 32 {  
        
            return Some(false) 
        }
        let original_digest_as_state: State = original_digest.to_vec().try_into().unwrap();

        // Check commitment to original digest is correct.
        let correct_last_commitment = PedersenCommitmentScheme::commit(
            &vk.commitment_key(), 
            &original_digest_as_state, 
            &proof.randomness_original_digest
        )?;
        if *(proof.commitments.last()?) != correct_last_commitment {
            
            return Some(false);
        }

        // Convert redacted bytes and selector into (padded) blocks.
        let (redacted_blocks,selector_blocks) = 
        crate::Padder::pad_block_and_selector(
            redacted_bytes, 
            selector);

        // Check proof is well-formed.
        if proof.midpeq_proofs.len()+1 != proof.commitments.len()
            || proof.midpeq_proofs.len() != redacted_blocks.len()
            || proof.midpeq_proofs.len() != selector_blocks.len()               
        {
            return None
        }
        
        // Prepare verifier's public inputs for the midpeq_proofs.
        let mut public_inputs:Vec<MidPublicInput> = Vec::new();
        for i in 0..proof.midpeq_proofs.len() {
            let pub_inp = MidPublicInput::new_public_input(
                &redacted_blocks[i], 
                &selector_blocks[i], 
                &proof.commitments[i+1], 
                &proof.commitments[i]);
            public_inputs.push(pub_inp);
        }

        // Compute verification results in parallel with rayon.
        let proof_verifications_opt: Vec<Option<bool>> = proof.midpeq_proofs.clone().into_par_iter()
        .zip(public_inputs.into_par_iter())
        .map(|(proof,pub_inp)|  T::verify(
            vk, 
            &pub_inp, 
            &proof)
        )
        .collect();

        // Return true iff all verifications are valid.
        if proof_verifications_opt.iter().any(|o| o.is_none()) 
        {
            return None
        }

        proof_verifications_opt
        .iter()
        .map(|o| o.unwrap())
        .reduce(|acc,is_valid| acc && is_valid)
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use crate::{cp::groth16::Groth16PeqScheme, PeqSnark};


    #[test]
    pub fn peq_cp_impl_works() -> () {

        // Data.
        let original_bytes = vec![0u8;55]; // One block.
        let mut redacted_bytes = vec![0u8;54];
        redacted_bytes.push(1); // Change last byte.
        let mut selector = vec![true;54];
        selector.push(false);

        let original_digest = sha2::Sha256::digest(&original_bytes).to_vec();

        let (pk,vk) = <Groth16PeqScheme as PeqSnark>::setup().unwrap();

        let proof = <Groth16PeqScheme as PeqSnark>::prove(
            &pk, 
            &redacted_bytes, 
            &selector, 
            &original_digest,
            &original_bytes).unwrap();

        let is_valid = <Groth16PeqScheme as PeqSnark>::verify(
            &vk, 
            &redacted_bytes, 
            &selector, 
            &original_digest, 
            &proof).unwrap();

        assert!(is_valid);
    }

}
