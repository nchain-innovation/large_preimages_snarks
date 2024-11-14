use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError};

use ff::{Field, PrimeFieldBits};
use halo2curves::bn256::Fr as BN256ScalarField;
use crate::{gadgets::bellpepper::num::ToNumGadget, Block, State};

pub struct Sha256CFGadget;

impl Sha256CFGadget {

    /// Wrapper of the bellpepper SHA256 compression function gagdet. 
    /// Midstates `h_in` are 8 `AllocatedNum` instead of 8 `UInt32`. 
    /// This is useful for e.g. Nova circuits. 
    pub fn apply_compression_function<CS: ConstraintSystem<BN256ScalarField>>(
        cs: &mut CS, 
        h_in: &[AllocatedNum<BN256ScalarField>],
        block_bits: &[Boolean])
      -> Result<Vec<AllocatedNum<BN256ScalarField>>,SynthesisError> {
    
        assert_eq!(h_in.len(),8);
        assert_eq!(block_bits.len(),512);
    
        // Input state (8 AllocatedNums) into 8 UInt32
        let mut h_in_uint32: Vec<UInt32> = Vec::new();
        for (i,h_in_i) in h_in.iter().enumerate() {
          
          let mut num_le_bits = h_in_i.to_bits_le_strict(
            cs.namespace(|| format!("input midstate h_in[{}] bits",i))
          )?;

          num_le_bits.truncate(32); // Each `AllocatedNum` holds 32 bits.
          h_in_uint32.push(UInt32::from_bits(&num_le_bits));
        }
            
        // Compute output state (as 8 Uint32)
        let h_out_uint32 = bellpepper::gadgets::sha256::sha256_compression_function(
            cs.namespace(|| "new sha256 midstate h_out"), 
            block_bits, 
            &h_in_uint32)?;
        
        let mut h_out_num_vec:Vec<AllocatedNum<BN256ScalarField>> = Vec::new();
    
        // Output state into 8 Nums.
        for h_out_uint32_i in h_out_uint32.iter() {

          let h_out_num_i = h_out_uint32_i.to_num(cs)?;

          h_out_num_vec.push(h_out_num_i);
        }

        Ok(h_out_num_vec)
    }

  pub fn pack_bytes(bytes: &[u8]) -> Vec<BN256ScalarField> {
    
    let bits_le = crate::Sha256CF::bytes_to_le_bits(bytes);

    Sha256CFGadget::pack_bits(&bits_le)
  }

  /// Encode bits as the little-endian representation of the output field elements. 
  /// Each element holds at most |char|-1 bits, where char is the characteristic of the field.
  /// This is an optimal encoding.
  pub fn pack_bits(bits_le: &[bool]) -> Vec<BN256ScalarField> {

    let char =  <BN256ScalarField as PrimeFieldBits>::char_le_bits().len();
    
    let mut fes: Vec<BN256ScalarField> = Vec::new();
    for chunk in bits_le.chunks(char-1) {
      let mut fe = <BN256ScalarField as Field>::ZERO;
      let mut coeff = <BN256ScalarField as Field>::ONE;
      for bit in chunk.iter() {
        if *bit { fe += coeff };
        coeff += coeff;
      }
      fes.push(fe);

      // Sanity check 
      for (bit_fe,bit_c) in fe.to_le_bits().iter().zip(chunk) {
          assert_eq!(*bit_fe,*bit_c);
        }
    }

    fes
  }

  pub fn encode_block(block: &Block) -> Vec<BN256ScalarField> {

    let block_vec: Vec<u64> = block.repr()
      .chunks_exact(8)
      .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
      .collect();
    let block_u64:[u64;8] = block_vec.try_into().unwrap();
    
    let fes_8: Vec<BN256ScalarField> =block_u64.iter().map(|u64| BN256ScalarField::from(*u64)).collect();
    
    fes_8
  }

  /// Maps 64 bools into the first 64 little-endian bits of the output field element. 
  pub fn encode_64_bits(bits: &[bool]) -> BN256ScalarField {
    assert_eq!(bits.len(),64);

    let mut bits_as_u64 = 0_u64;
    for (i,bit) in bits.iter().enumerate(){
      if *bit { bits_as_u64 |= 1_u64 << i; }
    }

    BN256ScalarField::from(bits_as_u64)
  }

   /// Encodes the bytes of a SHA256 state as 8 field elements.
   /// The i-th 32-bit digest word in the first 32 bits of 
   /// the field element. This is an inneficient encoding.
  pub fn encode_state(state: &State) -> Vec<BN256ScalarField> {
    
    state.repr()
    .iter()
    .map(|hi|
      {
        let hi_64: u64  = (*hi).into();
        BN256ScalarField::from(hi_64)
      })
    .collect()
  }

  /// The reverse of `encode_state`.
  pub fn decode_state(fes: &[BN256ScalarField]) -> State {
    assert_eq!(fes.len(),8);

    let digest_u32: Vec<u32> = fes.iter().map(|hi| 
      { 
        let hi_bits = PrimeFieldBits::to_le_bits(hi);
        let mut hi_as_u32 = 0_u32;
        for (i,bit) in hi_bits.iter().enumerate() {
          if *bit { hi_as_u32 |= 1 << i;}
        }
        hi_as_u32
      })
    .collect();

    digest_u32.try_into().unwrap()
  }
}