//! Nova IVC scheme.
//! 
//! 

pub mod circuit;

use std::collections::HashMap;

use crate::{ivc::accumulated_hash::AccumulatedHasher, NumberConstraints, PeqSnark, PrepareCircuits, Serialize};
use circuit::SelCircuit;

use nova_snark::{
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{
      circuit::TrivialCircuit,
      snark::RelaxedR1CSSNARKTrait,
      Engine,
    },
    CompressedSNARK, PublicParams, RecursiveSNARK,
  };

use flate2::{write::ZlibEncoder, Compression};

// The first source group of the BN256 elliptic curve.  (BN254??)
type BN256 = Bn256EngineKZG;
// An elliptic curve whose base field is the scalar field of `bn256` 
type Grumpkin = GrumpkinEngine;

// The scalar field of BN256
pub(crate) type BN256ScalarField = <BN256 as Engine>::Scalar;

type EEBN256 = nova_snark::provider::hyperkzg::EvaluationEngine<BN256>;
type EEGrumpkin = nova_snark::provider::ipa_pc::EvaluationEngine<Grumpkin>;

type NovaPublicParams = PublicParams<BN256,
                                     Grumpkin,
                                     SelCircuit,
                                     TrivialCircuit<<Grumpkin as Engine>::Scalar>
                                    >;
// Spartan for `SelCircuit`.
type SpartanPrimary = nova_snark::spartan::snark::RelaxedR1CSSNARK<BN256,EEBN256>; 
// Spartan for trivial circuit.
type SpartanSecondary = nova_snark::spartan::snark::RelaxedR1CSSNARK<Grumpkin,EEGrumpkin>; 

pub struct NovaProverKey {
    pp: NovaPublicParams,
    // SNARK prover key
    snark_pk: nova_snark::ProverKey<BN256,
                                    Grumpkin,
                                    SelCircuit,
                                    TrivialCircuit<<Grumpkin as Engine>::Scalar>,
                                    SpartanPrimary,
                                    SpartanSecondary
                                    >
}

impl PrepareCircuits<SelCircuit> for NovaProverKey {

    fn instantiate_prover_circuits(
        &self,
        original_bytes: &[u8],
        redacted_bytes: &[u8],
        selector: &[bool]
    ) -> Vec<SelCircuit> {

        assert_eq!(original_bytes.len(),redacted_bytes.len());
        assert_eq!(original_bytes.len(),selector.len());


        // Pad and compute blocks for original and redacted bytes, and selector bits.
        let (original_blocks,_) = crate::Padder::pad_block_and_selector(original_bytes, selector);
        let (redacted_blocks,sel_blocks) = crate::Padder::pad_block_and_selector(redacted_bytes, selector);

        let mut circuits:Vec<SelCircuit> = Vec::new();
        for i in 0..original_blocks.len() {
            // Sanity check. Padded selector should be blocks of 64 bits.
            //assert_eq!(original_blocks[i].len(),64);
            //assert_eq!(redacted_blocks[i].len(),64);
            assert_eq!(sel_blocks[i].len(),64);

            //let ob:[u8;64] = original_blocks[i].clone().try_into().unwrap();
            //let rb:[u8;64] = redacted_blocks[i].clone().try_into().unwrap();
            let sb:[bool;64] = sel_blocks[i].clone().try_into().unwrap();
            circuits.push(
                SelCircuit::new(&original_blocks[i],&redacted_blocks[i],&sb)
            );
        }
      circuits
    }
}

pub struct NovaVerifierKey {
    // SNARK verifier key
    snark_vk: nova_snark::VerifierKey<BN256,
                                      Grumpkin,
                                      SelCircuit,
                                      TrivialCircuit<<Grumpkin as Engine>::Scalar>,
                                      SpartanPrimary,
                                      SpartanSecondary
                                      >
}

#[derive(serde::Serialize)]
pub struct NovaProof {
    snark_proof: CompressedSNARK<BN256,
                                 Grumpkin,
                                 SelCircuit,
                                 TrivialCircuit<<Grumpkin as Engine>::Scalar>,
                                 SpartanPrimary,
                                 SpartanSecondary
                                >
}

impl Serialize for NovaProof {
    fn serialized_size(&self) -> usize {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        bincode::serialize_into(&mut encoder, &self).unwrap();
        let proof_encoded = encoder.finish().unwrap();
        proof_encoded.len()
    }
}

// Nova with Pedersen commitments in the Grumpkin-BN254 curve cycle, and with Spartan
// using HyperKZG. The (primary) [circuit][circuit::SelCircuit] is over the 
// BN254 scalar field. A trivial (secondary) circuit over the Grumpkin 
// scalar field is used to fold committed relaxed R1CS instances of 
// the primary circuit.
pub struct NovaPeqScheme;

impl PeqSnark for NovaPeqScheme {
    type ProverKey = NovaProverKey;

    type VerifierKey = NovaVerifierKey;

    type Proof = NovaProof;

    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)> {
        
        let pp_res = NovaPublicParams::setup(
            &SelCircuit::default(), 
            &TrivialCircuit::default(), 
            &SpartanPrimary::ck_floor(), 
            &SpartanSecondary::ck_floor());
        if pp_res.is_err() {return None;}
        let pp = pp_res.unwrap();

        let snark_keys_res = CompressedSNARK
        ::<BN256,Grumpkin,SelCircuit,TrivialCircuit<<Grumpkin as Engine>::Scalar>,SpartanPrimary,SpartanSecondary>
        ::setup(&pp);
        if snark_keys_res.is_err() {return None;}
        let snark_keys = snark_keys_res.unwrap();
        
        Some(
            (
                NovaProverKey{ pp, snark_pk: snark_keys.0  },
                NovaVerifierKey{ snark_vk: snark_keys.1 }
            )
        )
    }

    fn prove(
            pk: &Self::ProverKey, 
            redacted_bytes: &[u8],
            selector: &[bool],
            original_digest: &[u8],
            original_bytes: &[u8] 
    ) -> Option<Self::Proof> {
        
        let circuits = pk.instantiate_prover_circuits(
            original_bytes, 
            redacted_bytes, 
            selector
        );
        
        let circuit_secondary = TrivialCircuit::default();

        //  Primary and secondary original inputs.
        let z_0_primary = SelCircuit::get_z_0();
        let z_0_secondary = [<Grumpkin as Engine>::Scalar::zero()];
        
        // Prove base case.
        let mut recursive_snark =
            RecursiveSNARK::<BN256, Grumpkin, SelCircuit, TrivialCircuit<<Grumpkin as Engine>::Scalar>>
            ::new(&pk.pp,
        &circuits[0],
        &circuit_secondary,
        z_0_primary.as_slice(),
        &z_0_secondary,
        )
        .unwrap();
        
        // Fold circuits.
        for circuit in circuits.iter() {
            let res = recursive_snark.prove_step(&pk.pp, circuit, &circuit_secondary);
            assert!(res.is_ok());
        }

        // The original digest is the (last) output of the primary circuit.
        let computed_original_digest = SelCircuit::decode_state(recursive_snark.outputs().0);
        assert_eq!(computed_original_digest.to_be_bytes(),original_digest,"Input digest is invalid for the input bytes");


        // Generate spartan proof for knowledge of the folded witnesses.
        let res = CompressedSNARK::<_, _, _, _, SpartanPrimary, SpartanSecondary>::prove(&pk.pp, &pk.snark_pk, &recursive_snark);
        assert!(res.is_ok());
        let spartan_proof = res.unwrap();

        Some(NovaProof{
            snark_proof: spartan_proof
        })
    }

    fn verify(
        vk: &Self::VerifierKey,
        redacted_tx_bytes: &[u8],
        selector: &[bool],
        original_digest: &[u8],
        proof: &Self::Proof
    ) -> Option<bool> {

        let (blocks,s) = crate::Padder::pad_block_and_selector(redacted_tx_bytes, selector);
        
        // Verify proof on the instance (original_digets,a_out).
        let res = proof.snark_proof.verify(
            &vk.snark_vk,
            blocks.len(),
            &SelCircuit::get_z_0(),
            &[<Grumpkin as Engine>::Scalar::zero()],
          );

        // If invalid proof
        if res.is_err() { return Some(false) }

        let mut verified_z_out = res.unwrap().0;

        // Check verified digest.
        let verified_digest = SelCircuit::decode_state(&verified_z_out);
        if verified_digest.to_be_bytes() != original_digest { return Some(false) } // Check the verified digest against the digest of the proof.


        // Check verified accumulated hash a_N.
        let verified_a_out = verified_z_out.pop().unwrap();
        let recomputed_a_out = { // Recompute a_N from given redacted blocks and selector.
            let mut a_in = SelCircuit::get_z_0().pop().unwrap();
            let mut a_out = BN256ScalarField::zero();
            for (block,sel) in blocks.iter().zip(s.iter()) {
                let block_fes = SelCircuit::encode_block(&block);
                let selector_fe = SelCircuit::encode_selector(sel);
                a_out = AccumulatedHasher::hash_scalars(&a_in, block_fes.as_slice(), &[selector_fe]);
                a_in = a_out;
            }
            a_out
        };

        if verified_a_out != recomputed_a_out { return Some(false) } // Check the verified a_out against the just (correctly) recomputed a_out.

        Some(true)
    }
}

impl NumberConstraints for NovaPeqScheme {
    
    fn print() -> HashMap<String,usize> {

        let mut map = HashMap::new();
        map.insert("sha256".to_string(), SelCircuit::constraints_sha_midstate());
        map.insert("partial equality to preimage".to_string(), SelCircuit::constraints_partial_equality_to_preimage());
        map.insert("accumulated hash".to_string(),SelCircuit::constraints_accumulated_hash());

        map
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use crate::{ivc::nova::NovaPeqScheme, PeqSnark};

    use rand::Rng;


    #[test]
    pub fn peq_nova_impl_works() -> () {

        
        // Data.
        let mut rng = rand::thread_rng();
        let mut selector: Vec<bool> = Vec::new();
        let mut original_bytes: Vec<u8> = Vec::new();
        let mut redacted_bytes: Vec<u8> = Vec::new();
        for _i in 0..55 {
            let selector_bit = rng.gen_bool(0.5);
            original_bytes.push(0u8);
            if selector_bit { redacted_bytes.push(0u8); }
            else {
                    if rng.gen_bool(0.5) { // randomly change public byte.
                        redacted_bytes.push(1u8);
                    }
                    else { redacted_bytes.push(0u8); }
            }
            selector.push(false);

        }

        let original_digest = sha2::Sha256::digest(&original_bytes).to_vec();


        let (pk,vk) = <NovaPeqScheme as PeqSnark>::setup().unwrap();

        let proof = <NovaPeqScheme as PeqSnark>::prove(
            &pk, 
            &redacted_bytes, 
            &selector,
            &original_digest, 
            &original_bytes).unwrap();

        let is_valid = <NovaPeqScheme as PeqSnark>::verify(
            &vk, 
            &redacted_bytes, 
            &selector, 
            &original_digest, 
            &proof).unwrap();

        assert!(is_valid);

    }

}

