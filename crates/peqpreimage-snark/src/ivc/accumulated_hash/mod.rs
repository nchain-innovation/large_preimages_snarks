pub mod gadgets;

use crate::ivc::nova::BN256ScalarField;

use neptune::poseidon::PoseidonConstants;
use generic_array::typenum::U10;

pub struct AccumulatedHasher;

impl AccumulatedHasher {
    /// Poseidon hash over the scalar field of BN256.
    pub fn hash_scalars(
      a_in: &BN256ScalarField,
      block: &[BN256ScalarField],
      selector: &[BN256ScalarField]
    ) -> BN256ScalarField {
    
      // Prepare hash preimage.
      let scalars = Self::concat(a_in, block, selector);

      // Poseidon constants.
      if scalars.len() > 10 { panic!("Arity of Poseidon set to 10, but there are {} preimage scalars",scalars.len()) };
      let consts = PoseidonConstants::<BN256ScalarField, U10>::new();
      
      // Hash.
      let a_out= neptune::Poseidon::new_with_preimage(&scalars, &consts).hash();
      a_out
    }

    // Concatenate a_in, redacted_block, and selector block.
    fn concat<Value:Clone>(a_in: &Value, block: &[Value],selector: &[Value]) -> Vec<Value> {
      let mut res = vec![a_in.clone()];
      res.extend_from_slice(block);
      res.extend_from_slice(selector);

      res
    }
}