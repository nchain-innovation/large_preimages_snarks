pub mod gadgets;

use crate::ivc::nova::BN256ScalarField;

use neptune::{
    poseidon::PoseidonConstants, 
    sponge::{
      api::{IOPattern, SpongeAPI, SpongeOp},
      vanilla::{Mode::{self, Simplex}, Sponge, SpongeTrait},
    }, 
    Strength
  };

use generic_array::typenum::U24;

pub struct AccumulatedHasher;

impl AccumulatedHasher {
    /// Poseidon hash over the scalar field of BN256.
    pub fn hash_scalars(
      a_in: &BN256ScalarField,
      block: &[BN256ScalarField],
      selector: &[BN256ScalarField]
    ) -> BN256ScalarField {
    
      // Prepare hash preimage for neptune.
      let scalars = Self::concat(a_in, block, selector);

      // Derive parameters (constants and mode).
      let (pc,_,_,mode) = PoseidonHasher::derive_parameters(block.len()+selector.len()+1);

      // Vanilla neptune hash.
      let mut sponge = Sponge::new_with_constants(&pc, mode);
      let mut acc = ();
      let a_out = PoseidonHasher::apply_hash(&mut sponge,scalars.as_slice(),&mut acc);

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

struct PoseidonHasher;

impl PoseidonHasher {

  fn apply_hash<A: neptune::Arity<BN256ScalarField>,S:neptune::sponge::api::InnerSpongeAPI<BN256ScalarField,A>>(
    sponge: &mut S,
    scalars: &[S::Value], 
    acc: &mut S::Acc
  ) -> S::Value {

    let (_,num_absorbs,io_pattern,_) = Self::derive_parameters(scalars.len());

    sponge.start(io_pattern, None, acc);
    sponge.absorb( num_absorbs, scalars, acc);

    let mut a_out = sponge.squeeze(1, acc);
    sponge.finish(acc).unwrap();
  
    a_out.pop().unwrap()
  }

  // `scalars_length` is the number of scalar to be hashed.
  fn derive_parameters(scalars_length:usize) -> (PoseidonConstants<BN256ScalarField,U24>,u32,IOPattern,Mode) {
    let poseidon_constants =     Sponge::<BN256ScalarField,U24>::api_constants(Strength::Standard);
    let absorbs = scalars_length as u32;
    let io_pattern = IOPattern(vec![SpongeOp::Absorb(absorbs), SpongeOp::Squeeze(1u32)]);

    (poseidon_constants,absorbs,io_pattern,Simplex)
  }
}