//! Pedersen commitments over [`JubJub`][super::JubJub].
use ark_std::UniformRand;

use ark_crypto_primitives::{
    commitment::{
        pedersen::Commitment,
        CommitmentScheme
    }, 
    crh::pedersen::Window
};

use ark_serialize::*;

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha256_cf::State;

// JubJub curve
use super::JubJub;

#[derive(Clone)]
pub struct MidstateWindow;
/// Pedersen hash configuration. 
/// Only need room to commit to 256 bits.
impl Window for MidstateWindow {
    // The number of curve generators
    const NUM_WINDOWS: usize = 2;
    // The precomputed powers of each generator 
    const WINDOW_SIZE: usize =128;
}

pub(crate) type ArkPedersenJubJub = Commitment<JubJub,MidstateWindow>;

#[derive(Clone)]
pub struct PedersenKey(pub <ArkPedersenJubJub as CommitmentScheme>::Parameters);

#[derive(Clone,Debug,PartialEq,CanonicalSerialize)]
pub struct PedersenCommitment(pub <ArkPedersenJubJub as CommitmentScheme>::Output);

#[derive(Clone,Debug,CanonicalSerialize)]
pub struct PedersenRandomness(pub <ArkPedersenJubJub as CommitmentScheme>::Randomness);

/// Pedersen commitment scheme over [`JubJub`][super::JubJub].
/// 
/// This is a wrapper implementation of arkworks library.
pub struct PedersenCommitmentScheme;

/// Commitment scheme API
impl PedersenCommitmentScheme {

    pub fn generate_params() -> Option<PedersenKey> {
        match ArkPedersenJubJub::setup(&mut ChaCha20Rng::from_entropy()) {
            Err(_) => None,
            Ok(prms) => Some(PedersenKey(prms)),
        }
    }

    pub fn commit(ck: &PedersenKey, state: &State, rnd: &PedersenRandomness) -> Option<PedersenCommitment> {
        let state_le_bytes = state.to_le_bytes();
        match ArkPedersenJubJub::commit(&ck.0, &state_le_bytes, &rnd.0) {
            Err(_) => None,
            Ok(comm) => Some(PedersenCommitment(comm)),
        }     
    }
}

impl PedersenRandomness {
    /// Sample a random scalar over the JubJub curve.
    pub fn random_element() -> PedersenRandomness
    {
        PedersenRandomness(
            <ArkPedersenJubJub as CommitmentScheme>::Randomness::rand(
                &mut ChaCha20Rng::from_entropy()
            )    
        )
    }

    /// Outputs a default value
    pub fn default()-> PedersenRandomness 
    {
        PedersenRandomness(
            <<ArkPedersenJubJub as CommitmentScheme>::Randomness as Default>::default()
        )
    }
}

