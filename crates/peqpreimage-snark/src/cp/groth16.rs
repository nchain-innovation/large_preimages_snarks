
// Groth16 over BLS12 for the circuit `MidCircuit`]

use std::collections::HashMap;

use crate::NumberConstraints;

use super::{JubJubBaseField, BLS12, circuit::MidCircuit};
use super::{CpSnark, CpSnarkKey};
use super::pedersen::{PedersenCommitmentScheme, PedersenKey};
use ark_groth16::Groth16;
use ark_snark::SNARK;

use rand_chacha::ChaChaRng;

/// Wrapped Groth16 prover key and the commitment key for midstates.
pub struct Groth16ProverKey {
    pk: <Groth16<BLS12> as SNARK<JubJubBaseField>>::ProvingKey,
    ck: PedersenKey
}

pub struct Groth16VerifierKey {
    vk: <Groth16<BLS12> as SNARK<JubJubBaseField>>::VerifyingKey,
    ck: PedersenKey
}

impl CpSnarkKey for Groth16ProverKey {
    fn commitment_key(&self) -> PedersenKey {
        self.ck.clone()
    }
}

impl  CpSnarkKey for Groth16VerifierKey {
    fn commitment_key(&self) -> PedersenKey {
        self.ck.clone()
    }
}

/// Implementation of trait `PeqSnark` via the commit-and-prove approach with Groth16. This 
/// yimplementation produces as many proofs as SHA56 blocks in the preimage. Groth16 is 
/// instantiated over BLS12 and the commitment scheme for blocks is Pedersen. 
#[derive(Clone)]
pub struct Groth16PeqScheme;

/// This implementation is a building block. 
impl CpSnark for Groth16PeqScheme {
    type ProverKey = Groth16ProverKey;

    type VerifierKey = Groth16VerifierKey;

    type Proof = <Groth16<BLS12> as SNARK<JubJubBaseField>>::Proof;

    fn setup() -> Option<(Self::ProverKey,Self::VerifierKey)> { 
        let ck = PedersenCommitmentScheme::generate_params()?; 
        let circuit = MidCircuit::satisfiable_circuit(&ck);
        let mut rng = <ChaChaRng as rand::SeedableRng>::from_entropy();

        let keys_res = <Groth16<BLS12> as SNARK<JubJubBaseField>>::circuit_specific_setup(circuit, &mut rng);
        if keys_res.is_err() { return None }
        let (pk,vk) = keys_res.unwrap();
        
        Some((
            Groth16ProverKey{ pk, ck: ck.clone() },
            Groth16VerifierKey{ vk, ck }
        ))
    }

    fn prove(
            pk: &Self::ProverKey, 
            public_input: super::MidPublicInput,
            private_input: super::MidPrivateInput
        ) 
        -> Option<Self::Proof> {
            
            let circuit = MidCircuit::new(&public_input,&private_input,&pk.commitment_key());

            let mut rng = <ChaChaRng as rand::SeedableRng>::from_entropy();

            <Groth16<BLS12> as SNARK<JubJubBaseField>>::prove(
                &pk.pk, 
                circuit, 
                &mut rng
            ).ok()
    }

    fn verify(
        vk: &Self::VerifierKey,
        pub_inp: &super::MidPublicInput,
        proof: &Self::Proof
    ) -> Option<bool> {
        let pub_inp_fes = pub_inp.to_field_elements();

        <Groth16<BLS12> as SNARK<JubJubBaseField>>::verify(
            &vk.vk, 
            &pub_inp_fes, 
            proof
        ).ok()
    }
}

impl NumberConstraints for Groth16PeqScheme {
    
    fn print() -> std::collections::HashMap<String,usize> {

        let mut map = HashMap::new();

        map.insert("sha256".to_string(), MidCircuit::constraints_correct_midstates_gadget());
        map.insert("partial equality to preimage".to_string(), MidCircuit::constraints_peq_gadget());
        map.insert("commitment to midstate".to_string(), MidCircuit::constraints_correct_commitments_gadget());

        map
    }
}

#[cfg(test)]
mod tests {

    use super::Groth16PeqScheme;
    use crate::cp::CpSnark;

    #[test]
    pub fn groth16_midpeq_works() -> () {
   
        let (pk,vk) = <Groth16PeqScheme as CpSnark>::setup().unwrap();
        let circuit = crate::cp::circuit::MidCircuit::satisfiable_circuit(&pk.ck);

        let proof = <Groth16PeqScheme as CpSnark>::prove(
            &pk,
            circuit.public_input.clone(),
            circuit.private_input.clone()
        ).unwrap();

        let public_input_verif = circuit.public_input.clone();

        let is_valid = <Groth16PeqScheme as CpSnark>::verify(
            &vk,
            &public_input_verif,
            &proof
        ).unwrap();

        assert!(is_valid);

        ()
    }
}