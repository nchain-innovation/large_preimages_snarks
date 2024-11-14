mod cp;
mod ivc;

// Expose default implementations.

/// The default implementation of [PeqSnark] via 
/// a commit-and-prove approach. This implementation produces 
/// as many proofs as SHA56 blocks in the preimage.
/// 
/// The default implementation is set to Groth16.
pub type DefaultCommitandProvePeqScheme = cp::groth16::Groth16PeqScheme;

/// The default implementation of [PeqSnark] via an
/// incrementally verified (IVC) scheme. This implementation produces 
/// a single proof.
/// 
/// The default implementation is set to Nova.
pub type DefaultIvcPeqScheme = ivc::nova::NovaPeqScheme;

use std::collections::HashMap;

use sha256_cf::Block;


/// The SNARK for the partial-equality to SHA256 preimage circuit satisfiability.
/// 
/// Partial equality of original and redacted bytes is done at the byte level.
pub trait PeqSnark {
    type ProverKey;
    type VerifierKey;
    type Proof: Serialize;

    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)>;

    fn prove(
            pk: &Self::ProverKey, 
            redacted_bytes: &[u8],
            selector: &[bool],
            original_digest: &[u8],
            original_bytes: &[u8] 
            ) -> Option<Self::Proof>;
    fn verify(
        vk: &Self::VerifierKey,
        redacted_bytes: &[u8],
        selector: &[bool],
        original_digest: &[u8],
        proof: &Self::Proof
    ) -> Option<bool>;
}

// Preparation of a vector of circuits `C` used by the prover
// that is given by the prover key that implements this trait.
pub(crate) trait PrepareCircuits<C> {
    
    fn instantiate_prover_circuits(
        &self,
        original_bytes: &[u8],
        redacted_bytes: &[u8],
        selector: &[bool]
    ) -> Vec<C>;
}

/// For benchmarks.
/// 
/// Only size of the serialized proof is required.
pub trait Serialize {
    fn serialized_size(&self) -> usize;
}

/// For benchmarks.
pub trait NumberConstraints {

    /// Prints a map gadget_name -> number_constraints used by the implementation.
    fn print() -> HashMap<String,usize>;
}

pub(crate) struct Padder;

impl Padder {

    // Outputs SHA256 blocks with padding from the passed bytes. 
    // Extra selector (true) bits are added to account for padding.
    fn pad_block_and_selector(bytes: &[u8], selector: &[bool],) -> (Vec<Block>,Vec<Vec<bool>>) 
    {
        assert_eq!(bytes.len(),selector.len());
        
        let message_bitlength:u64 = (bytes.len()*8).try_into().unwrap();

        // Collect bytes into chunks of 64 bytes each.
        let mut blocks_bytes: Vec<Vec<u8>> = bytes
        .chunks(64)
        .map(|c| c.to_vec())
        .collect();

        // Collect all but last blocks
        let mut blocks:Vec<Block> = Vec::new();
        for block_bytes in blocks_bytes[0..blocks_bytes.len()-1].iter() {
            blocks.push(block_bytes.clone().try_into().unwrap());
        }

        // Pad last block and add the result to blocks.
        let last_block_bytes = blocks_bytes.last().unwrap().clone();
        let mut last_blocks_with_padding = sha256_cf::Sha256CF::pad_last_block_bytes(
            &blocks_bytes.pop().unwrap(),
            message_bitlength
        );
        let number_paded_bytes = last_blocks_with_padding.len()*64 - last_block_bytes.len();
        blocks.append(&mut last_blocks_with_padding);
       
        // Add selector bits for the padded bytes. Equality is enforced.
        let mut padded_selector = selector.to_vec();
        padded_selector.extend(vec![true;number_paded_bytes]);
        
        assert_eq!(padded_selector.len()%64,0);
        let sel_blocks: Vec<Vec<bool>> = padded_selector
        .chunks(64)
        .map(|c| c.to_vec())
        .collect();

        // Sanity check.
        assert_eq!(blocks.len(),sel_blocks.len());


        //(blocks_bytes,sel_blocks)
        (blocks,sel_blocks)
    }
}