use crate::ivc::nova::BN256ScalarField;

use super::{AccumulatedHasher,PoseidonHasher};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use neptune::{
  circuit2::Elt, 
  sponge::{circuit::SpongeCircuit,vanilla::SpongeTrait,
}};

pub struct AccumulatedHasherGadget;

impl AccumulatedHasherGadget {

  /// The R1CS analog of [AccumulatedHasher::hash_scalars].
  pub fn hash_scalars<CS:ConstraintSystem<BN256ScalarField>>(
      cs: &mut CS,
      a_in: &AllocatedNum<BN256ScalarField>, 
      block: &[AllocatedNum<BN256ScalarField>],
      selector: &[AllocatedNum<BN256ScalarField>]
  ) -> Result<AllocatedNum<BN256ScalarField>,SynthesisError> {

    // Prepare hash preimage for neptune.
    let a_in_elt = Self::to_elts(&[a_in.clone()]).pop().unwrap();
    let block_elts = Self::to_elts(block);
    let selector_elts = Self::to_elts(selector);
    let scalars = AccumulatedHasher::concat(&a_in_elt, block_elts.as_slice(), selector_elts.as_slice());

    // Derive parameters (constants and mode).
    let (pc,_,_,mode) = PoseidonHasher::derive_parameters(block.len()+selector.len()+1);

    // Neptune hash circuit.
    let mut sponge = SpongeCircuit::new_with_constants(&pc, mode);

    let mut ns = cs.namespace(|| "hashing redacted block and selector");
    let acc = &mut ns;
    let a_out_elt = PoseidonHasher::apply_hash(&mut sponge,scalars.as_slice(),acc);

    let a_out = Elt::ensure_allocated(&a_out_elt, &mut ns.namespace(|| "ensure a_out allocated"), true);

    a_out
  }

  fn to_elts(scalars: &[AllocatedNum<BN256ScalarField>]) -> Vec<Elt<BN256ScalarField>> {
    let elts: Vec<Elt<BN256ScalarField>> = scalars.iter()
    .map(|scalar|{Elt::Allocated(scalar.clone())})
    .collect();

    elts
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