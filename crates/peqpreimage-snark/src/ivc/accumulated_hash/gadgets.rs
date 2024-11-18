use crate::ivc::nova::BN256ScalarField;

use super::{AccumulatedHasher,PoseidonConstants,U10};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};

pub struct AccumulatedHasherGadget;

impl AccumulatedHasherGadget {

  /// The R1CS analog of [AccumulatedHasher::hash_scalars].
  pub fn hash_scalars<CS:ConstraintSystem<BN256ScalarField>>(
      cs: &mut CS,
      a_in: &AllocatedNum<BN256ScalarField>, 
      block: &[AllocatedNum<BN256ScalarField>],
      selector: &[AllocatedNum<BN256ScalarField>]
  ) -> Result<AllocatedNum<BN256ScalarField>,SynthesisError> {

    // Prepare hash preimage.
    let scalars = AccumulatedHasher::concat(a_in, block, selector);
    
    // Poseidon constants.
    if scalars.len() > 10 { panic!("Arity of Poseidon set to 10, but there are {} preimage scalars",scalars.len()) };
    let consts = PoseidonConstants::<BN256ScalarField, U10>::new();
    
    // Hash.
    neptune::circuit2::poseidon_hash_allocated(cs.namespace(|| "hashing redacted block and selector"), scalars, &consts)
  }
}

#[cfg(test)]
mod tests {

    use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
    use sha256_cf::Block;

    use super::AccumulatedHasher;
    use super::AccumulatedHasherGadget;
    use crate::ivc::nova::{circuit::SelCircuit, BN256ScalarField};


  #[test]
  fn poseidon_gadget_works() -> () {

    let a_in = BN256ScalarField::zero();
    let block = SelCircuit::encode_block(&Block::default());
    let selector = SelCircuit::encode_selector(&[true;64]);

    let a_out = AccumulatedHasher::hash_scalars(&a_in, block.as_slice(), &[selector]);

    let mut cs = TestConstraintSystem::<BN256ScalarField>::default();
    let a_in_all = SelCircuit::allocate_field_elements(&mut cs.namespace(|| "a_in"), &[a_in]).unwrap().pop().unwrap();
    let block_all = SelCircuit::allocate_field_elements(&mut cs.namespace(|| "block"), block.as_slice()).unwrap();
    let selector_all = SelCircuit::allocate_field_elements(&mut cs.namespace(|| "selector"), &[selector]).unwrap();

    let a_out_all = AccumulatedHasherGadget::hash_scalars(&mut cs.namespace(|| "poseidon"), &a_in_all, block_all.as_slice(), selector_all.as_slice()).unwrap();

    assert_eq!(a_out,a_out_all.get_value().unwrap());
  }
}