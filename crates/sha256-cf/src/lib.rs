//! SHA256 compression function and R1CS gadget.

use std::ops::Deref;
pub mod gadgets;

// Initialization vector of SHA256.
const IV:[u32;8] = [
    0x6a09e667, 
    0xbb67ae85, 
    0x3c6ef372, 
    0xa54ff53a, 
    0x510e527f, 
    0x9b05688c, 
    0x1f83d9ab, 
    0x5be0cd19,
];

/// Stateless SHA256 compression function.
pub struct Sha256CF;

impl Sha256CF {

    /// A stateless wrapper of the RustCrypto SHA256 implementation.
    /// # Example
    /// ```
    /// use sha2::Sha256; // RustCrypto.
    /// use sha256_cf::{Sha256CF,Digest}; // This crate. 
    /// 
    /// let bytes = [0u8;55]; // One block
    /// let padded_block = Sha256CF::pad_last_block_bytes(&bytes, 55*8); // Pad the block.
    /// let init_state = Sha256CF::get_iv();
    /// let digest: sha256_cf::Digest = Sha256CF::apply_compression_function(&init_state, &padded_block[0]).into(); // Compute stateless digest.
    /// 
    /// let rust_crypto_digest_bytes = <Sha256 as sha2::Digest>::digest(bytes);
    /// assert_eq!(*digest.to_be_bytes(),*rust_crypto_digest_bytes);
    /// ```
    pub fn apply_compression_function(current_state: &State, block: &Block) -> State {

        let mut new_state_repr = current_state.repr();
        let block_repr = block.repr();
        let ga = sha2::digest::generic_array::GenericArray::clone_from_slice(&block_repr);
        
        sha2::compress256(&mut new_state_repr, &[ga]);
        
        let new_state:State = new_state_repr.to_vec().try_into().unwrap();
        new_state
    }
    
    /// Pad the last block. This assumes messages are (blocks of) byte arrays. 
    /// If last block > 56 bytes, two 64-byte blocks are returned. Else, 
    /// a single 64-byte padded block is returned.
    // sha256 padding appends bit '1' followed by k zeros, where k = 448-L-1 mod 512 and k in [0,448)
    // and then appends the message length in big endian as a 64-bit array (prepended with zeros if needed).
    pub fn pad_last_block_bytes(block_bytes: &[u8],message_bitlength: u64) -> Vec<Block> {
        if block_bytes.len() > 64 {panic!("Unpadded block bytes must have at most 64 bytes")};

        let mut num_blocks = 1;
        if block_bytes.len() >= 56 { num_blocks = 2; }
        let mut padded_bytes = block_bytes.to_vec();
    
        padded_bytes.push(0x80); // 0x80 = 0b10000000. First padded byte.
        padded_bytes.append(&mut vec![0u8;64*num_blocks-block_bytes.len()-9]);
        padded_bytes.append(&mut message_bitlength.to_be_bytes().to_vec()); // Last 8 padded bytes.
        
        let mut blocks = Vec::new();
        
        if num_blocks == 1 {
            let block: Block = padded_bytes.try_into().unwrap();
            blocks.push(block);
        }
        else {
          let block2_bytes = padded_bytes.split_off(64);
          blocks.push(padded_bytes.try_into().unwrap());
          blocks.push(block2_bytes.try_into().unwrap());
        }

        blocks
    }

    /// Convert bytes into bits in little-endian ordering.
    pub fn bytes_to_le_bits(bytes: &[u8])
    -> Vec<bool> {

        bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte  & (1u8<<i) == 1u8)))
        .collect()
  }

  pub fn get_iv() -> State {
    IV.into()
  }
}

#[derive(Clone,Copy,PartialEq,Debug)]
pub struct Block([u8;64]);

impl Block {

     /// Returns the representation of block.
     pub fn repr(&self) -> [u8;64] {
        self.0
    }

}

impl Default for Block {
    fn default() -> Self {
        Self([0u8;64])
    }
}

impl TryFrom<Vec<u8>> for Block {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        
        if value.len() != 64 {
            Err("A SHA256 block must have 64 bytes")
        }
        else {
            let bytes:[u8;64] = value.try_into().unwrap();
            Ok(Block(bytes))
        }
    }
}

impl From<[u8;64]> for Block {
    fn from(value: [u8;64]) -> Self {
        Block(value)
    }
}

#[derive(Clone,Copy,PartialEq,Debug)]
pub struct State([u32;8]);

impl State {

    pub fn to_le_bytes(&self) -> Vec<u8> {
        
        let state_le_bytes:Vec<u8> = self.0.iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();

        state_le_bytes
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        
        let state_be_bytes:Vec<u8> = self.0.iter()
        .flat_map(|word| word.to_be_bytes())
        .collect();

        state_be_bytes
    }

    /// Returns the representation of an state.
    pub fn repr(&self) -> [u32;8] {
        self.0
    }
}

impl TryFrom<Vec<u8>> for State {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {

        if value.len()!= 32 {
            Err("A SHA256 state must have 32 bytes")
        } 
        else {
            let state_vec:Vec<u32> = value.chunks(4)
            .map(|word_be_bytes| {
            let word_be_bytes_arr:[u8;4] = word_be_bytes.try_into().unwrap();
            u32::from_be_bytes(word_be_bytes_arr)
            })
            .collect();
        
            let state:[u32;8] = state_vec.try_into().unwrap();
            Ok(State(state))
        }
    }
}

impl TryFrom<Vec<u32>> for State {
    type Error = &'static str;

    fn try_from(value: Vec<u32>) -> Result<Self, Self::Error> {
        if value.len()!= 8 {
            Err("A SHA256 state must have 8 32-bit unsigned integers")
        } 
        else {
            let state:[u32;8] = value.try_into().unwrap();
            Ok(State(state))
        }
    }
}

impl From<[u32;8]> for State {
    fn from(value: [u32;8]) -> Self {
        State(value)
    }
}

#[derive(Clone,Copy,PartialEq,Debug)]
pub struct Digest(State);

// Digests are really states.
impl Deref for Digest {
    type Target = State;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        State::try_from(value).map(|st| Digest(st))
    }
}

impl From<State> for Digest {
    fn from(value: State) -> Self {
        Digest(value)
    }
}

#[cfg(test)]
    pub mod tests {

        use super::*;
        
        // Taken from https://www.di-mgt.com.au/sha_testvectors.html
        fn sha256_test_vector_448_bits() -> ([u8;56],Digest) {
            
            let message_448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"; 
            let state: State = [
                                    0x248d6a61 as u32, 
                                    0xd20638b8, 
                                    0xe5c02693,
                                    0x0c3e6039, 
                                    0xa33ce459, 
                                    0x64ff2167, 
                                    0xf6ecedd4,
                                    0x19db06c1
                                  ].into();

            (*message_448,state.into())
        }
        #[test]
        fn padding_and_compression_function_works() {

            let (message_448,correct_digest) = sha256_test_vector_448_bits();
            let padded_blocks = Sha256CF::pad_last_block_bytes(&message_448, 448);

            //let mut pb_iter = padded_blocks.chunks(64);
            //let block1:[u8;64]  = pb_iter.next().unwrap().try_into().expect("slice with incorrect length");
            //let block2:[u8;64]  = pb_iter.next().unwrap().try_into().expect("slice with incorrect length");

            // Compute digest iteratively
            let init_state = Sha256CF::get_iv();
            let midstate = Sha256CF::apply_compression_function(&init_state,&padded_blocks[0]);
            let digest: Digest = Sha256CF::apply_compression_function(&midstate, &padded_blocks[1]).into();

            assert_eq!(digest,correct_digest);
        }
    }
