
use super::BN256ScalarField;
use sha256_cf::{gadgets::bellpepper::sha256::Sha256CFGadget, Block, State};
use crate::ivc::accumulated_hash::gadgets::AccumulatedHasherGadget;

use bellpepper_core::{boolean::{AllocatedBit, Boolean}, 
                      ConstraintSystem, 
                      SynthesisError};
use bellpepper::{gadgets::num::AllocatedNum, util_cs::bench_cs::BenchCS};
use nova_snark::traits::circuit::StepCircuit;
use halo2curves::ff::Field;


#[derive(Clone)]
/// The commit-to-selector step circuit C_{sel}. The circuit logic 
/// is implemented in [SelCircuit::synthesize]. 
pub struct SelCircuit {
  // Non-deterministic advice for the incremental step
  original_block: Vec<BN256ScalarField>,
  redacted_block: Vec<BN256ScalarField>,
  selector_block: BN256ScalarField
}

impl Default for SelCircuit{
    fn default() -> Self {
      SelCircuit::new(&[0u8;64].into(), &[1u8;64].into(), &[true;64])
    }
}

/// Constructor and IO packing.
impl SelCircuit {
 /// Creates an incremental step circuit from the given non-deterministic advice
 pub fn new(original_block: &Block, 
        redacted_block: &Block,
        selector_block: &[bool;64]) 
    -> Self {

      Self {
        original_block: SelCircuit::encode_block(original_block),
        redacted_block: SelCircuit::encode_block(redacted_block),
        selector_block: SelCircuit::encode_selector(selector_block)
      }
  }

  pub fn encode_block(block: &Block) -> Vec<BN256ScalarField> {
    
    Sha256CFGadget::encode_block(block)
  }

  pub fn encode_selector(selector: &[bool]) -> BN256ScalarField {

    Sha256CFGadget::encode_64_bits(selector)
  }

  /// Outputs the bytes of a SHA256 state, which are encoded in 
  /// the first 8 field elements of the circuit output.
  pub fn decode_state(circuit_output: &[BN256ScalarField]) -> State {
    
    Sha256CFGadget::decode_state(&circuit_output[0..circuit_output.len()-1])
  }

  /// Provides the original input (h_0,a_0) of the circuit C_{sel}.
  /// h_0 is the IV of sha256, a_0 = 0 (arbitrary value). 
  pub fn get_z_0() -> Vec<BN256ScalarField> {
    vec![
      //sha256 IV:
      BN256ScalarField::from(0x6a09e667), // h0
      BN256ScalarField::from(0xbb67ae85), // h1
      BN256ScalarField::from(0x3c6ef372), // h2
      BN256ScalarField::from(0xa54ff53a), // h3
      BN256ScalarField::from(0x510e527f), // h4
      BN256ScalarField::from(0x9b05688c), // h5
      BN256ScalarField::from(0x1f83d9ab), // h6
      BN256ScalarField::from(0x5be0cd19), // h7
      //a_0:
      BN256ScalarField::ZERO
    ]
  }
}

// Input allocation methods
impl SelCircuit {

  /// Allocates a vector of bits
  pub fn allocate_bits<CS: ConstraintSystem<BN256ScalarField>>(
    cs: &mut CS,
    bits:&[Option<bool>]
  ) -> Result<Vec<Boolean>,SynthesisError> {
    
    bits.iter()
      .enumerate()
      .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("Allocating bit {}",i)), *b))
      .map(|b| b.map(Boolean::from))
      .collect::<Result<Vec<_>, _>>()
  }

  /// Allocate a vector of field elements
  pub fn allocate_field_elements<CS:ConstraintSystem<BN256ScalarField>>(
    cs: &mut CS,
    fes: &[BN256ScalarField]
  ) -> Result<Vec<AllocatedNum<BN256ScalarField>>,SynthesisError> {
    
      (0..fes.len())
      .map(|i| AllocatedNum::alloc(cs.namespace(|| format!("Allocating field element {}", i)), || Ok(fes[i])))
      .collect::<Result<Vec<_>, _>>()
  }
}

/// Circuit gadgets
impl SelCircuit {

  /// Compute a new sha256 midstate h_out from the given input block m*_in and input midstate h_in.
  /// It returns h_out as 8 fresh `AllocatedNum`s.
  fn compute_sha_midstate<CS: ConstraintSystem<BN256ScalarField>>(
    cs: &mut CS, 
    h_in: &[AllocatedNum<BN256ScalarField>],
    original_block_bits: &[Boolean])
  -> Result<Vec<AllocatedNum<BN256ScalarField>>,SynthesisError> {

     Sha256CFGadget::apply_compression_function(cs, h_in, original_block_bits)
  }

  /// Computes the accumulated hash a_i = Hash(a_{i-1},m*_i,\sigma_i) 
  /// from the current redacted block m*_i and selector \sigma_i.
  /// It returns the newly allocated a_i.
  pub fn compute_accumulated_hash<CS:ConstraintSystem<BN256ScalarField>>(
    cs: &mut CS,
    a_in: &AllocatedNum<BN256ScalarField>,
    redacted_block_fes:&[AllocatedNum<BN256ScalarField>],
    selector_block_fes: &[AllocatedNum<BN256ScalarField>]) 
    -> Result<AllocatedNum<BN256ScalarField>,SynthesisError> {

      AccumulatedHasherGadget::hash_scalars(cs, a_in, redacted_block_fes, selector_block_fes)
  }

  /// If i-th selector bit = 1, next 8 bits (next byte) of original & redacted blocks are enforced to be equal.
  /// Else, we don't care (redacted byte). 
  pub fn enforce_partial_equality<CS:ConstraintSystem<BN256ScalarField>>(
    cs: &mut CS,
    original_block_bits: &[Boolean],
    redacted_block_bits: &[Boolean],
    selector_block_bits: &[Boolean]
  ) 
  -> Result<(),SynthesisError> {

    assert_eq!(original_block_bits.len(),512);
    assert_eq!(redacted_block_bits.len(),512);
    assert_eq!(selector_block_bits.len(),64);

    // Enforce 0 = (m[k] XOR m*[k]) AND sigma[k] for each k = 8i+j
    for i in 0..64 {
        for j in 0..8 {
          let xor = Boolean::xor(cs.namespace(|| format!("XOR of the {}-th bits",8*i+j)), 
          &original_block_bits[8*i+j],
          &redacted_block_bits[8*i+j])?;

          let and  = Boolean::and(cs.namespace(|| format!("AND of the {}-th bits",8*i+j)), 
          &xor,
          &selector_block_bits[i])?;

          Boolean::enforce_equal(
            cs.namespace(|| format!("partial equality of {}-th bits",8*i+j)),
            &Boolean::Constant(false),
            &and
          )?
        } 
    }

    Ok(())
  }

  /// Converts the input field elements into big-endian `Boolean`s 
  /// allocated in the constrain system `cs`.
  pub fn field_elements_to_bits_be<CS:ConstraintSystem<BN256ScalarField>>(
    cs: &mut CS,
    block_fes: &[AllocatedNum<BN256ScalarField>]
  ) -> Result<Vec<Boolean>,SynthesisError> {

    let mut bits: Vec<Boolean> = Vec::new();

    for fe in block_fes {
      let mut fe_le_bits = fe.to_bits_le_strict(cs.namespace(|| "field element to bits"))?;

      
      fe_le_bits.truncate(64);
      if block_fes.len() > 1 { fe_le_bits.reverse(); }

      bits.append(&mut fe_le_bits);
    }

    Ok(bits)
  }

}

/// Output number of R1CS constraints for each gadget.
/// For benchmarks.
impl SelCircuit {

  pub fn constraints_sha_midstate() -> usize {
    let mut benchcs = BenchCS::<BN256ScalarField>::new();

    let mut h_in: Vec<BN256ScalarField> = Vec::new();
    for _i in 0..8 {h_in.push(BN256ScalarField::from(0));}
    let mut bits: Vec<Option<bool>> = Vec::new();
    for _i in 0..512 {bits.push(Some(false));}
    let h_in_alloc = SelCircuit::allocate_field_elements(&mut benchcs, h_in.as_slice()).unwrap();
    let bits_alloc = SelCircuit::allocate_bits(&mut benchcs, bits.as_slice()).unwrap();
    let _mid = SelCircuit::compute_sha_midstate(&mut benchcs, &h_in_alloc, bits_alloc.as_slice());

    benchcs.num_constraints()
  }

  pub fn constraints_accumulated_hash() -> usize {
    let mut benchcs = BenchCS::<BN256ScalarField>::new();

    
    let a_in = BN256ScalarField::from(0);
    let mut block_fes: Vec<BN256ScalarField> = Vec::new();
    for _i in 0..8 {block_fes.push(BN256ScalarField::from(0));}
    let mut selector_fes: Vec<BN256ScalarField> = Vec::new();
    for _i in 0..64 {selector_fes.push(BN256ScalarField::from(0));}

    let a_in_alloc = SelCircuit::allocate_field_elements(&mut benchcs, &[a_in]).unwrap().pop().unwrap();
    let block_fes_alloc = SelCircuit::allocate_field_elements(&mut benchcs, block_fes.as_slice()).unwrap();
    let selector_fes_alloc = SelCircuit::allocate_field_elements(&mut benchcs, selector_fes.as_slice()).unwrap();


    let _mid = SelCircuit::compute_accumulated_hash(
      &mut benchcs, 
      &a_in_alloc, 
      block_fes_alloc.as_slice(),
      selector_fes_alloc.as_slice()
    );

    benchcs.num_constraints()
  }

  pub fn constraints_partial_equality_to_preimage() -> usize {

    let mut benchcs = BenchCS::<BN256ScalarField>::new();

    let ob_alloc = SelCircuit::allocate_bits(
      &mut benchcs.namespace(|| "allocate original bits"), 
    &[Some(true);512])
    .unwrap();
    let rb_alloc = SelCircuit::allocate_bits(
      &mut benchcs.namespace(|| "allocate redacted bits"), 
    &[Some(true);512])
    .unwrap();  
    let sel_alloc = SelCircuit::allocate_bits(
      &mut benchcs.namespace(|| "allocate selector bits"), 
    &[Some(true);64])
    .unwrap();

    let _ = SelCircuit::enforce_partial_equality(&mut benchcs.namespace(|| "Partial equality constraints"), ob_alloc.as_slice(), rb_alloc.as_slice(), sel_alloc.as_slice());
    
    benchcs.num_constraints()
  }
}

impl StepCircuit<BN256ScalarField> for SelCircuit {
  fn arity(&self) -> usize {
    9
  }

  /// Sythesize the circuit for a computation step and return variable that corresponds 
  /// to the output z_i = (h_i,a_i) of the i-th step where
  /// - h_i := sha256(m_i,h_{i-1}) // m_i current original block
  /// - a_i := Poseidon(a_{i-1},m*_i,sigma_i) // m*_i current redacted block, sigma_i current selector block
  fn synthesize<CS: ConstraintSystem<BN256ScalarField>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<BN256ScalarField>],
  ) -> Result<Vec<AllocatedNum<BN256ScalarField>>, SynthesisError> {
    
    // z_in provides the running SHA256 midstates h_{i-1} (8 AllocatedNums) 
    // and an accumulated hash a_{i-1}. a_{i-1} is the last item.
    assert_eq!(z_in.len(), 9);
    let mut h_in = z_in.to_vec();
    let a_in = h_in.pop().unwrap();

    // Allocate non-deterministic input. 
    let original_block_fes = SelCircuit::allocate_field_elements(cs, &self.original_block)?;
    let redacted_block_fes = SelCircuit::allocate_field_elements(cs, &self.redacted_block)?;
    let selector_block_fes =  SelCircuit::allocate_field_elements(cs, &[self.selector_block])?;

    // Step 1: Enforce partial equality of blocks. 
    let original_block_bits = SelCircuit::field_elements_to_bits_be(cs, &original_block_fes)?;
    let redacted_block_bits = SelCircuit::field_elements_to_bits_be(cs, &redacted_block_fes)?;
    let selector_block_bits = SelCircuit::field_elements_to_bits_be(cs, &selector_block_fes)?;
    SelCircuit::enforce_partial_equality(
      cs,
      &original_block_bits,
      &redacted_block_bits,
      &selector_block_bits
    )?;

    // Step 2: Compute sha256 midstate.
    let h_out = SelCircuit::compute_sha_midstate(
      cs, 
      &h_in,
      &original_block_bits)?;

    // Step 3: Compute running hash for redacted block and selector.
    let a_out = SelCircuit::compute_accumulated_hash(
      cs, 
      &a_in, 
      &redacted_block_fes, 
      &selector_block_fes
    )?;

    let mut z_out = h_out.clone();
    z_out.push(a_out);
    
    Ok(z_out)
  }
}