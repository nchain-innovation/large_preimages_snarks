//! R1CS gadget based on arkworks.
// DISCLAIMER: 
//  This is a direct copy of
//      https://github.com/arkworks-rs/crypto-primitives/blob/v0.4.0/src/crh/sha256/constraints.rs#L65
// and tooling from 
//      https://github.com/arkworks-rs/crypto-primitives/blob/v0.4.0/src/crh/sha256/r1cs_utils.rs
//  We put it here because we need the R1CS of the SHA256 compression function, and function `update_state` from  the first link above is private and stateful.

use ark_std::vec::Vec;
use ark_ff::PrimeField;

use ark_r1cs_std::bits::{boolean::Boolean, uint32::UInt32, uint8::UInt8, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;
use core::iter;
use std::marker::PhantomData;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
    
/// Extra traits not automatically implemented by UInt32
trait UInt32Ext<ConstraintF: PrimeField>: Sized {
    /// Right shift
    fn shr(&self, by: usize) -> Self;

    /// Bitwise NOT
    fn not(&self) -> Self;

    /// Bitwise AND
    fn bitand(&self, rhs: &Self) -> Result<Self, SynthesisError>;

    /// Converts from big-endian bytes
    fn from_bytes_be(bytes: &[UInt8<ConstraintF>]) -> Result<Self, SynthesisError>;

    
}

impl<ConstraintF: PrimeField> UInt32Ext<ConstraintF> for UInt32<ConstraintF> {
    fn shr(&self, by: usize) -> Self {
        assert!(by < 32);

        let zeros = iter::repeat(Boolean::constant(false)).take(by);
        let new_bits: Vec<_> = self
            .to_bits_le()
            .into_iter()
            .skip(by)
            .chain(zeros)
            .collect();
        UInt32::from_bits_le(&new_bits)
    }

    fn not(&self) -> Self {
        let new_bits: Vec<_> = self.to_bits_le().iter().map(Boolean::not).collect();
        UInt32::from_bits_le(&new_bits)
    }

    fn bitand(&self, rhs: &Self) -> Result<Self, SynthesisError> {
        let new_bits: Result<Vec<_>, SynthesisError> = self
            .to_bits_le()
            .into_iter()
            .zip(rhs.to_bits_le())
            .map(|(a, b)| a.and(&b))
            .collect();
        Ok(UInt32::from_bits_le(&new_bits?))
    }

    fn from_bytes_be(bytes: &[UInt8<ConstraintF>]) -> Result<Self, SynthesisError> {
        assert_eq!(bytes.len(), 4);

        let mut bits: Vec<Boolean<ConstraintF>> = Vec::new();
        for byte in bytes.iter().rev() {
            let b: Vec<Boolean<ConstraintF>> = byte.to_bits_le()?;
            bits.extend(b);
        }
        Ok(UInt32::from_bits_le(&bits))
    }
}

pub struct Sha256CFGadget<ConstraintF:PrimeField>(PhantomData<ConstraintF>);

impl<ConstraintF: PrimeField> Sha256CFGadget<ConstraintF> {
    /// Stateless SHA256 compression function. It outputs the new state.
    // Wikipedia's pseudocode is a good companion for understanding the below
    // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    pub fn apply_compression_function_gadget(
        current_state: &[UInt32<ConstraintF>],
        block: &[UInt8<ConstraintF>],
    ) 
    -> Result<Vec<UInt32<ConstraintF>>, SynthesisError> {   
        if current_state.len() != 8  {panic!("sha256 states are 8 32-bit words")};
        if block.len() != 64 {panic!("sha256 blocks are 64 bytes")};

        let mut w = vec![UInt32::constant(0); 64];
        for (word, chunk) in w.iter_mut().zip(block.chunks(4)) {
            *word = UInt32::from_bytes_be(chunk)?;
        }

        for i in 16..64 {
            let s0 = {
                let x1 = w[i - 15].rotr(7);
                let x2 = w[i - 15].rotr(18);
                let x3 = w[i - 15].shr(3);
                x1.xor(&x2)?.xor(&x3)?
            };
            let s1 = {
                let x1 = w[i - 2].rotr(17);
                let x2 = w[i - 2].rotr(19);
                let x3 = w[i - 2].shr(10);
                x1.xor(&x2)?.xor(&x3)?
            };
            w[i] = UInt32::addmany(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1])?;
        }

        let mut h = current_state.to_vec();
        for i in 0..64 {
            let ch = {
                let x1 = h[4].bitand(&h[5])?;
                let x2 = h[4].not().bitand(&h[6])?;
                x1.xor(&x2)?
            };
            let ma = {
                let x1 = h[0].bitand(&h[1])?;
                let x2 = h[0].bitand(&h[2])?;
                let x3 = h[1].bitand(&h[2])?;
                x1.xor(&x2)?.xor(&x3)?
            };
            let s0 = {
                let x1 = h[0].rotr(2);
                let x2 = h[0].rotr(13);
                let x3 = h[0].rotr(22);
                x1.xor(&x2)?.xor(&x3)?
            };
            let s1 = {
                let x1 = h[4].rotr(6);
                let x2 = h[4].rotr(11);
                let x3 = h[4].rotr(25);
                x1.xor(&x2)?.xor(&x3)?
            };
            let t0 =
                UInt32::addmany(&[h[7].clone(), s1, ch, UInt32::constant(K[i]), w[i].clone()])?;
            let t1 = UInt32::addmany(&[s0, ma])?;

            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = UInt32::addmany(&[h[3].clone(), t0.clone()])?;
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = UInt32::addmany(&[t0, t1])?;
        }

        let mut new_state: Vec<UInt32<ConstraintF>> = vec![];
        for i in 0..8 {
            new_state.push(
                UInt32::addmany(&[current_state[i].clone(), h[i].clone()])?
            );
        }
        Ok(new_state)
    }
}
#[cfg(test)]
    pub mod tests {

        use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, uint8::UInt8, R1CSVar};
        use ark_relations::r1cs::*;

        use ark_ed_on_bls12_381::Fq as CircuitField;
        use crate::{Block, State};

        use super::*;
        
        #[test]
        fn sha256_gadget_works() {
            
            // Compute the SHA256 new state with our exposed compression function
            let block: Block = [0u8;64].to_vec().try_into().unwrap();
            let current_state: State = [1u32;8].to_vec().try_into().unwrap(); // Arbitrary current state
            let new_state =  crate::Sha256CF::apply_compression_function(&current_state, &block);

            // Compute the SHA256 new state R1CS variable with the gagdget
            let cs = ConstraintSystem::<CircuitField>::new_ref(); // Set constraint field to JubJub
            let mut block_var:Vec<UInt8<CircuitField>> = vec![];
            for byte in block.repr().iter() {
                block_var.push(
                    UInt8::<CircuitField>::new_input(cs.clone(), || Ok(byte)).unwrap()
                );
            }
            let mut current_state_var:Vec<UInt32<CircuitField>> = vec![];
            for current_word in current_state.repr().iter() {
                current_state_var.push(
                    UInt32::<CircuitField>::new_input(cs.clone(), || Ok(current_word)).unwrap()
                );
            }
            let new_state_var = Sha256CFGadget::apply_compression_function_gadget(&current_state_var, &block_var).unwrap();

            // Check new state variable equals the new state
            for (new_word_var,new_word) in new_state_var.iter().zip(new_state.repr().iter()) {
                
                assert_eq!(*new_word,
                            R1CSVar::value(new_word_var).unwrap()
                        );
            }
        }
    }
