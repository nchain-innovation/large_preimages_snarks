//! R1CS constraints for the commit-to-midstate circuit over the [`CircuitField`][super::CircuitField].

use ark_crypto_primitives::commitment::CommitmentScheme;
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef,ConstraintSystem, SynthesisError};

use ark_crypto_primitives::commitment::{
    pedersen::constraints::CommGadget, 
    CommitmentGadget};

// The analog of the JubJub base field in R1CS
pub(crate) use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubBaseFieldVar;
use ark_std::iterable::Iterable;

use sha256_cf::{State,Block,gadgets::arkworks::sha256::Sha256CFGadget};

use super::JubJubBaseField;
use super::JubJub;
use crate::cp::pedersen::*;
// Ark commitment gadget for our own configuration
type ArkPedersenGadget = CommGadget<JubJub, JubJubBaseFieldVar, MidstateWindow>;
type CommitmentKeyVar = <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::ParametersVar;
type RandomnessVar = <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::RandomnessVar;
type CommitmentVar = <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::OutputVar;


/// The public input of the MidPeq circuit.
///
/// * Redacted block*.
/// 
/// * Selector vector σ. Equality is enforced at the byte level:
///  
///     * If σ[j] = 0 the j-th original byte block[j] HAS BEEN redacted. The j-th redacted byte block*[j] 
///       can take any value.
///
///     * Else σ[j] = 1 and equality block[j] = block*[j] is enforced.
/// 
/// * Commitments to midstates com_cur, com_prev.

#[derive(Clone,Debug)]
pub struct MidPublicInput
{
    redacted_block: Block, //remove // [u8;64],
    selector_block: [bool;64],
    current_mid_comm: PedersenCommitment,
    previous_mid_comm: PedersenCommitment,
}

impl MidPublicInput {

    /// Construct a public input (instance) for [MidCircuit].
    pub fn new_public_input(
        redacted_block: &Block,
        sel_block: &[bool],
        cur_mid_comm: &PedersenCommitment,
        prev_mid_comm: &PedersenCommitment)
        -> MidPublicInput {
            assert_eq!(sel_block.len(),64);
            
            let sel_block_ar:[bool;64] = sel_block.try_into().unwrap();
            
            MidPublicInput{
                redacted_block: *redacted_block,
                selector_block: sel_block_ar,
                current_mid_comm: cur_mid_comm.clone(),
                previous_mid_comm: prev_mid_comm.clone()
            }
    }

    pub fn current_state_commitment(&self) -> PedersenCommitment {
        self.current_mid_comm.clone()
    }

    pub fn previous_state_commitment(&self) -> PedersenCommitment {
        self.previous_mid_comm.clone()
    }

    /// This method produces the public input for the arkworks SNARK verifier.
    /// 
    /// The [field][super::CircuitField] has 255 bits.
    /// We encode a redacted block* (64 bytes) as three field elements, and selector σ (64 bits) as one field element.
    /// Both are treated as little endian arrays.
    /// The commitments are two field elements each (x,y coordinates).
    /// 
    /// The output vector has 8 elements, in the following order: 
    ///     [block*_fe1,block*_fe2,block*_fe3,selector_fe,prev_comm_x,prev_comm_y,cur_comm_x,cur_comm_y]
    pub fn to_field_elements(&self)-> Vec<JubJubBaseField> {

        // Redacted block: three field elements to allocate 64 little-endian bytes
        let block_fe1 =<JubJubBaseField as PrimeField>::from_le_bytes_mod_order(&self.redacted_block.repr()[0..31]);
        let block_fe2 = <JubJubBaseField as PrimeField>::from_le_bytes_mod_order(&self.redacted_block.repr()[31..62]);
        let block_fe3 = <JubJubBaseField as PrimeField>::from_le_bytes_mod_order(&self.redacted_block.repr()[62..64]);
        
        // Selector block: one field element to allocate 64 bits (8 bytes). 
        // An optmimized allocation is to put it together with the third block field element above.
        let bigint = BigInteger::from_bits_le(&self.selector_block);
        let selector_fe = <JubJubBaseField as PrimeField>::from_bigint(bigint).unwrap();

        // Field elements of Pedersen commitments
        let prev_comm_fes =
            <<ArkPedersenJubJub as CommitmentScheme>::Output as ToConstraintField<JubJubBaseField>>::
            to_field_elements(&self.previous_mid_comm.0).unwrap();
        let cur_comm_fes = 
            <<ArkPedersenJubJub as CommitmentScheme>::Output as ToConstraintField<JubJubBaseField>>::
            to_field_elements(&self.current_mid_comm.0).unwrap();

        let mut elements = vec![];
        elements.extend_from_slice(&[
            block_fe1,
            block_fe2,
            block_fe3,
            selector_fe
        ]);
        elements.extend_from_slice(&prev_comm_fes);
        elements.extend_from_slice(&cur_comm_fes);

        elements
    }
}

/// The private input of the MidPeq circuit.
/// 
/// * Original block (512 bits).
/// 
/// * Current and previous SHA256 midstates mid_cur, mid_prev, (256 bits each). 
/// 
/// * Current and previous randomness to commit to midstates r_cur, r_prev.
#[derive(Clone,Debug)]
pub struct MidPrivateInput
{
    original_block: Block,
    current_mid: State,
    previous_mid: State,
    current_randomness: PedersenRandomness,
    previous_randomness: PedersenRandomness
}

impl MidPrivateInput {
    
    /// Constructs a private input (witness) for [`MidCircuit`][crate::mid::circuit::MidCircuit]
    pub fn new_private_input(
        original_block: &Block,
        current_mid: &State,
        previous_mid: &State,
        current_randomness: &PedersenRandomness,
        previous_randomness: &PedersenRandomness
    ) 
    -> MidPrivateInput {

        MidPrivateInput { 
            original_block: *original_block,
            current_mid: *current_mid, 
            previous_mid: *previous_mid,
            current_randomness: current_randomness.clone(), 
            previous_randomness: previous_randomness.clone()
        }
    }

    pub fn current_state(&self) -> State {
        self.current_mid
    }

    pub fn current_randomness(&self) -> PedersenRandomness {
        self.current_randomness.clone()
    }
}

/// The MidPeq circuit with [Pedersen commitments][PedersenCommitmentScheme] over [JubJub]
/// 
/// [Public input][crate::mid::MidPublicInput]: block*, com_cur, com_prev, σ
/// 
/// [Private input][crate::mid::MidPrivateInput]: block, mid_cur, mid_prev, r_cur, r_prev
/// 
/// Constraints: 
/// 
/// 1. Check that 0 = (block* + block)·σ
/// 
/// 2. Check that mid_cur = Sha256CF(mid_prev,block)
/// 
/// 3. Check that com_cur = Pedersen::commit(mid_cur,r_cur) 
/// 
/// 4. Check that com_prev = Pedersen::commit(mid_prev,r_prev)
#[derive(Clone)]
pub struct MidCircuit{
    pub private_input: MidPrivateInput,
    pub public_input: MidPublicInput,
    /// The commitment key is in the R1CS as constant.
    commitment_key: PedersenKey,
}


impl MidCircuit {
    pub fn new(public_input: &MidPublicInput, private_input: &MidPrivateInput, commitment_key: &PedersenKey) -> Self {
        MidCircuit {
            public_input: public_input.clone(),
            private_input: private_input.clone(),
            commitment_key: commitment_key.clone()
        }
    }
}

///  Gadget constraints
impl MidCircuit{

    /// Returns the bytes of the redacted midstate block*.
    /// 
    /// The bytes of the first field element, followed by the bytes of the second field element, followed by the first two bytes of the third field element (in little endian).
    pub fn redacted_block_to_bytes(block_fe: &[FpVar<JubJubBaseField>]) 
    -> Result<Vec<UInt8<JubJubBaseField>>,SynthesisError> {
        // We encode 64-byte midstates as three field elements
        assert_eq!(block_fe.len(),3);
        
        // First 31 bytes
        let fe1 = block_fe[0].clone();
        let mut redacted_bytes = 
            ToBytesGadget::<JubJubBaseField>::to_bytes(&fe1)?;
        
        assert!(redacted_bytes.len()>30);
        let _ = redacted_bytes.split_off(31);
        
        // Bytes 32 to 62
        let fe2 = block_fe[1].clone();
        let mut bytes_32_63 = 
            ToBytesGadget::<JubJubBaseField>::to_bytes(&fe2)?;

        assert!(bytes_32_63.len()>30);
        let _ = bytes_32_63.split_off(31);
        redacted_bytes.append(&mut bytes_32_63.clone());

        // Bytes 63,64
        let fe3 = block_fe[2].clone();
        let bytes_63_64 = 
            ToBytesGadget::<JubJubBaseField>::to_bytes(&fe3)?;
        redacted_bytes.push(bytes_63_64[0].clone());
        redacted_bytes.push(bytes_63_64[1].clone());

        Ok(redacted_bytes)
    }

    /// Returns the selector block vector σ, which are the first 64 bits of the input field element (in little endian). 
    pub fn selector_to_bits(selector_fe: &FpVar<JubJubBaseField>) 
    -> Result<Vec<Boolean<JubJubBaseField>>,SynthesisError> {
        
        let mut selector_bits = vec![];

        let mut bits = ToBitsGadget::to_bits_le(selector_fe)?;
        let _ = bits.split_off(64);
        selector_bits.append(&mut bits.clone());

        Ok(selector_bits)
    }

    /// Output `true` if  block*[j] = block[j] when σ[j] = 1, thus the set bits of σ are the positions where equality is enforced. Here block*, block, and σ must be all slices of length 64. 
    pub fn blocks_are_partially_equal(
        original_bytes: &[UInt8<JubJubBaseField>],
        redacted_bytes: &[UInt8<JubJubBaseField>],
        selector_bits: &[Boolean<JubJubBaseField>])
        -> Result<Boolean<JubJubBaseField>, SynthesisError> {
            assert_eq!(original_bytes.len(),redacted_bytes.len());
            assert_eq!(redacted_bytes.len(),selector_bits.len());
            assert_eq!(selector_bits.len(),64);

            let mut partially_equal = Boolean::<JubJubBaseField>::TRUE;
            
            for ((original_byte, redacted_byte),selector_bit) in
            original_bytes.iter()
            .zip(redacted_bytes.iter())
            .zip(selector_bits.iter())
            {
                // Need to impose this constraint even if selection bit is unset (σ[j] = 0) as we cannot select dynamically based on input.
                let equal_byte = redacted_byte.xor(original_byte)?.is_eq(&UInt8::constant(0))?;

                // If σ[j] = 1 enforce the equal byte constraint. Else (σ[j] = 0) select TRUE anyways.  
                let equal_selected_byte = selector_bit.select(
                    &equal_byte,
                    &Boolean::<JubJubBaseField>::TRUE
                    )?;

                partially_equal = partially_equal.and(&equal_selected_byte)?
            }
    
            Ok(partially_equal)
        }

    /// Output `true` if mid_cur = [Sha256CFGadget][crate::sha256_cf::constraints::Sha256CFGadget](block,mid_prev). 
    /// Midstates are slices of length 8, and block a slice of length 64. 
    pub fn midstate_is_correct(
        mid_cur: &[UInt32<JubJubBaseField>], 
        mid_prev: &[UInt32<JubJubBaseField>],
        original_block: &[UInt8<JubJubBaseField>])
        -> Result<Boolean<JubJubBaseField>, SynthesisError> {
            assert_eq!(mid_cur.len(),mid_prev.len());
            assert_eq!(mid_prev.len(),8);

            assert_eq!(original_block.len(),64);

            let mut midstate_is_correct = Boolean::<JubJubBaseField>::TRUE;
            
            // Compute the correct current midstate.
            let correct_mid_cur =Sha256CFGadget::<JubJubBaseField>::
            apply_compression_function_gadget(mid_prev, original_block)?;

            // Compute whether they are equal or not.
            for (word, correct_word) in 
                mid_cur.iter().zip(correct_mid_cur.iter()) {
                    
                    let equal_words = word.is_eq(correct_word)?;
                    midstate_is_correct = midstate_is_correct.and(&equal_words)?;
            }

            Ok(midstate_is_correct)
        }

    /// Output `true` if com = PedHash(ck,mid,r) 
    pub fn commitment_is_correct(
        ck: &CommitmentKeyVar,
        mid: &[UInt32<JubJubBaseField>],
        randomness: &RandomnessVar,
        commitment: &[FpVar<JubJubBaseField>]
    )
    -> Result<Boolean<JubJubBaseField>, SynthesisError> {
         
        let mid_bytes = Self::midstate_to_bytes(mid);
        
        // Compute correct commitment.
        let correct_commitment = 
            <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::
            commit(ck, &mid_bytes, randomness)?;

        let correct_commitment_fes = 
        <<ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::OutputVar 
        as ToConstraintFieldGadget<JubJubBaseField>>::to_constraint_field(&correct_commitment)?;

        let mut are_equal = vec![];
        assert_eq!(correct_commitment_fes.len(),commitment.len());
        for (fe_correct,fe) in 
        correct_commitment_fes.iter().zip(commitment.iter()) {
            let is_equal = 
            <FpVar<JubJubBaseField> as EqGadget<JubJubBaseField>>::is_eq(fe_correct, fe)?;

            are_equal.push(is_equal);
        }

        Boolean::<JubJubBaseField>::
        kary_and(&are_equal)?
        .is_eq(&Boolean::<JubJubBaseField>::TRUE)
    }

    //This should be consistent with PedersenCommitmentScheme::midstate_to_le_bytes used when committing.
   fn midstate_to_bytes(midstate: &[UInt32<JubJubBaseField>]) -> Vec<UInt8<JubJubBaseField>> {
    
    let midstate_bytes:Vec<UInt8<JubJubBaseField>> = 
    midstate
    .iter()
    .flat_map(|word| 
                ark_r1cs_std::bits::ToBytesGadget::to_bytes(&word).unwrap()
            )
    .collect();

    midstate_bytes
   } 
}

/// R1CS input allocation methods.
impl MidCircuit {

    /// Allocate the public inputs (instance) of the circuit in `cs`.
    /// The redacted block (three field elements)
    /// The selector block (one field element)
    /// The two commitments (two field elements each)
    pub fn allocate_public_inputs_as_field_elements(
        pub_input: &MidPublicInput, 
        cs: ConstraintSystemRef<JubJubBaseField>)
    -> ark_relations::r1cs::Result<(
                                    Vec<FpVar<JubJubBaseField>>,
                                    FpVar<JubJubBaseField>,
                                    Vec<FpVar<JubJubBaseField>>,
                                    Vec<FpVar<JubJubBaseField>>
                                )> 
    {
        let input_fes = pub_input.to_field_elements();

        let mut redacted_block_fes_var: Vec<FpVar<JubJubBaseField>> = vec![];
        
        // Allocate first three field elements for block*
        for fe in input_fes.iter().take(3) {
            redacted_block_fes_var.push(FpVar::<JubJubBaseField>::new_input(cs.clone(), || Ok(fe))?);
        }

        // Allocate fourth field element for selector bits σ
        let selector_fe_var = FpVar::<JubJubBaseField>::new_input(cs.clone(), || Ok(input_fes[3]))?;

        // Commitments are the last 4 field elements of the input
        let mut prev_comm_fes_var: Vec<FpVar<JubJubBaseField>> = vec![];
        for fe in input_fes.iter().skip(4) {
            prev_comm_fes_var.push(FpVar::<JubJubBaseField>::new_input(cs.clone(), || Ok(fe))?);
        }
        let cur_comm_fes_var = prev_comm_fes_var.split_off(2);
    
        Ok((
            redacted_block_fes_var,
            selector_fe_var,
            prev_comm_fes_var,
            cur_comm_fes_var
        ))
    }

    // Allocate the redacted block encoded as three field elements as public input (instance) in `cs`.
    // For tests
    fn allocate_redacted_block_as_field_elements(pub_input: &MidPublicInput,cs: ConstraintSystemRef<JubJubBaseField>) 
    -> ark_relations::r1cs::Result<Vec<FpVar<JubJubBaseField>>> {
        let input_fes = pub_input.to_field_elements();

        let mut redacted_block_fe_var: Vec<FpVar<JubJubBaseField>> = vec![];
        
        // Allocate only field elements for block*
        for fe in input_fes.iter().take(3) {
            redacted_block_fe_var.push(FpVar::<JubJubBaseField>::new_input(cs.clone(), || Ok(fe))?);
        }
        
        Ok(redacted_block_fe_var)
    }
   
    // Allocate selector bits σ encoded as a field element as public input (instance) in `cs`.
    // For tests
    fn allocate_selector_field_element(pub_input: &MidPublicInput,cs: ConstraintSystemRef<JubJubBaseField>) 
    -> ark_relations::r1cs::Result<FpVar<JubJubBaseField>> {
        
        let inputs_fe = pub_input.to_field_elements();
        
        // Allocate only field element for selector bits σ
        FpVar::<JubJubBaseField>::new_input(cs.clone(), || Ok(inputs_fe[3]))
    }


    // Allocate the commitment as public input (instance) in `cs`.
    // For tests
    fn allocate_commitment(cs:ConstraintSystemRef<JubJubBaseField>,commitment:&PedersenCommitment)
    -> ark_relations::r1cs::Result<CommitmentVar> {
        let commitment_var = 
            <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::
            OutputVar::new_input(cs.clone(), || Ok(commitment.0))?;

        Ok(commitment_var)
    }

    /// Allocate the original block as witness in `cs`.
    pub fn allocate_original_block(cs: ConstraintSystemRef<JubJubBaseField>, original_block: &Block) 
    -> ark_relations::r1cs::Result<Vec<UInt8<JubJubBaseField>>> {
        let mut block_var = vec![];
        for byte in original_block.repr().iter() {
                block_var.
                    push(UInt8::<JubJubBaseField>::new_witness(cs.clone(), || Ok(byte))?);
        }    
    
        Ok(block_var)
    }

    /// Allocate a midstate as witness in `cs`.
    pub fn allocate_midstate(cs: ConstraintSystemRef<JubJubBaseField>, mid: &State)
    -> ark_relations::r1cs::Result<Vec<UInt32<JubJubBaseField>>>
    {
        let mut mid_var = vec![];
        for word in mid.repr().iter() {
            mid_var.
                push(UInt32::new_witness(cs.clone(), || Ok(word))?);
        }
        Ok(mid_var)
    }

    /// Allocate randomness used to commit to a midstate as witness in `cs`.
    pub fn allocate_randomness(cs: ConstraintSystemRef<JubJubBaseField>,randomness: &PedersenRandomness) 
    -> ark_relations::r1cs::Result<RandomnessVar> 
    {
        <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::
            RandomnessVar::new_witness(cs.clone(), || Ok(randomness.0.clone()))
    }

    /// Allocate the commitment key as constant in `cs`.
    pub fn allocate_commitment_key(cs: ConstraintSystemRef<JubJubBaseField>, commitment_key:&PedersenKey)
    -> ark_relations::r1cs::Result<CommitmentKeyVar> {
        let commitment_key_var = <ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::
            ParametersVar::new_constant(cs.clone(), commitment_key.0.clone())?;
        
        Ok(commitment_key_var)
    }
}

/// Output number of R1CS constraints for each gadget.
/// For benchmarks.
impl MidCircuit {
    
    pub fn constraints_peq_gadget() -> usize {

        let (pub_inp,priv_inp) = 
            MidCircuit::dummy_inputs();

        let cs = ConstraintSystem::<JubJubBaseField>::new_ref();

        let orig_block= Self::allocate_original_block(
            cs.clone(), 
            &priv_inp.original_block
        ).unwrap();

        // We don't want to include constraints for redacted_block_to_bytes gadget. 
        // Thus, allocate redacted block bytes as witness -- we don't care for number of constraints.
        let red_block= Self::allocate_original_block(
            cs.clone(), 
            &priv_inp.original_block
        ).unwrap();

        // We don't want to include constraints for selector_to_bits gadget.
        // Thus, directly allocate selector bits.
        let mut selector: Vec<Boolean<JubJubBaseField>> = vec![];
        for bit in pub_inp.selector_block.iter() {
            selector.
                push(Boolean::<JubJubBaseField>::new_input(cs.clone(), || Ok(bit)).unwrap());
        }

        let _ = Self::blocks_are_partially_equal(
            &orig_block,
            &red_block,
            &selector
        );

        cs.num_constraints()
    }

    /// Constraints of gadget [MidCircuit::midstate_is_correct]
    pub fn constraints_correct_midstates_gadget() -> usize {

        let (_,priv_inp) = 
            MidCircuit::dummy_inputs();

        let cs = ConstraintSystem::<JubJubBaseField>::new_ref(); // Set constraint field to JubJub

        let mid_prev = Self::allocate_midstate(
            cs.clone(), 
            &priv_inp.previous_mid
        ).unwrap();

        let mid_cur = Self::allocate_midstate(
            cs.clone(), 
            &priv_inp.current_mid
        ).unwrap();

        let original_block = Self::allocate_original_block(
            cs.clone(),
            &priv_inp.original_block
        ).unwrap();

        // It won't be satsified, but we don't care for number of constraints.
        let _ = Self::midstate_is_correct(&mid_cur, &mid_prev, &original_block);

        cs.num_constraints()
    }

    /// Accounts for two gadgets [MidCircuit::commitment_is_correct]
    pub fn constraints_correct_commitments_gadget() -> usize {

        let ck = PedersenCommitmentScheme::generate_params().unwrap();
        let (pub_inp,priv_inp) = 
            MidCircuit::dummy_inputs();

        let cs = ConstraintSystem::<JubJubBaseField>::new_ref(); // Set constraint field to JubJub
    
        let comm_key = Self::allocate_commitment_key(
            cs.clone(), 
            &ck
        ).unwrap();

        let rand = Self::allocate_randomness(
            cs.clone(), 
            &priv_inp.current_randomness)
        .unwrap();

        let midstate= Self::allocate_midstate(
            cs.clone(), 
            &priv_inp.current_mid
        ).unwrap();
        
        let commitment = Self::allocate_commitment(
            cs.clone(), 
            &pub_inp.current_mid_comm
        ).unwrap();

        let commitment_fes = <<ArkPedersenGadget as CommitmentGadget<ArkPedersenJubJub,JubJubBaseField>>::OutputVar 
        as ToConstraintFieldGadget<JubJubBaseField>>::to_constraint_field(&commitment).unwrap();
        
        let _ = Self::commitment_is_correct(&comm_key, &midstate, &rand, &commitment_fes);

        2*cs.num_constraints()
    }
    // For tests
    fn dummy_inputs() -> (MidPublicInput,MidPrivateInput) {
        let block = [0u8;64].into();
        let selector = [false;64];
        let ck = PedersenCommitmentScheme::generate_params().unwrap();
        let rnd = PedersenRandomness::random_element();
        let mid: State = [0u32;8].into();
        let comm = PedersenCommitmentScheme::commit(&ck,&mid,&rnd).unwrap();

        (
            MidPublicInput::new_public_input(
                &block, 
                &selector, 
                &comm, 
                &comm),
            MidPrivateInput::new_private_input(
                &block, 
                &mid, 
                &mid, 
                &rnd, 
                &rnd
            )
        )
    }

    /// To instantiate the circuit in setup.
    pub(crate) fn satisfiable_circuit(ck: &PedersenKey) -> MidCircuit {
        
        let orig_block:Block = [0u8;64].into(); // 0-byte block
        let mut red_block_bytes = orig_block.repr();
        red_block_bytes[0] = 2;
        red_block_bytes[31] = 3;
        red_block_bytes[63] = 4;
        let red_block:Block = red_block_bytes.into();
        let mut selector = [true;64];
        
        // Equality is skipped on redacted bytes:
        selector[0] = false;
        selector[31] = false;
        selector[63] = false;

        // Apply compression function
        let init_state = sha256_cf::Sha256CF::get_iv();
        let cur_mid = sha256_cf::Sha256CF::apply_compression_function(
            &init_state, 
            &orig_block
        );

        // Commit
        let cur_rnd = PedersenRandomness::random_element();
        let prev_rnd = PedersenRandomness::random_element();
        
        let prev_comm = PedersenCommitmentScheme::commit(ck,&init_state,&prev_rnd).unwrap();
        let cur_comm = PedersenCommitmentScheme::commit(ck,&cur_mid,&cur_rnd).unwrap();

        // Create circuit inputs
        let pub_inp = MidPublicInput::new_public_input(
            &red_block, 
            &selector,
            &cur_comm,
            &prev_comm
        );
        let priv_inp = MidPrivateInput::new_private_input(
            &orig_block,
            &cur_mid,
            &init_state,
            &cur_rnd,
            &prev_rnd
        );
        
        MidCircuit
        {
            private_input: priv_inp,
            public_input: pub_inp,
            commitment_key: ck.clone()
        }
    }
}

impl  ConstraintSynthesizer<JubJubBaseField> for MidCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<JubJubBaseField>) -> ark_relations::r1cs::Result<()> {
        
        // ***
        // Allocate public inputs in the R1CS. 
        // ***
        let (
            redacted_block_fes_var,
            selector_block_fe_var,
            com_prev_var,
            com_cur_var
        ) = 
            MidCircuit::allocate_public_inputs_as_field_elements(
                &self.public_input, 
                cs.clone()
            )?;
        
        // ***
        // Allocate private inputs in the R1CS. 
        // ***
        let original_block_var = MidCircuit::allocate_original_block(
            cs.clone(),
            &self.private_input.original_block
        )?;

        let mid_prev_var = MidCircuit::allocate_midstate(
            cs.clone(),
            &self.private_input.previous_mid
        )?;

        let mid_cur_var = MidCircuit::allocate_midstate(
            cs.clone(),
            &self.private_input.current_mid
        )?;

        let r_prev_var = MidCircuit::allocate_randomness(
            cs.clone(), 
            &self.private_input.previous_randomness
        )?;
        
        let r_cur_var = MidCircuit::allocate_randomness(
            cs.clone(), 
            &self.private_input.current_randomness
        )?;
        
        let ck_var = MidCircuit::allocate_commitment_key(
            cs.clone(), 
            &self.commitment_key
        )?;
        
        // ***
        // Enforce constraints. 
        // ***

        let redacted_block_var = MidCircuit::redacted_block_to_bytes(&redacted_block_fes_var)?;

        let selector_block_var = MidCircuit::selector_to_bits(&selector_block_fe_var)?;

        let bytes_are_partially_equal = MidCircuit::blocks_are_partially_equal(&original_block_var, &redacted_block_var, &selector_block_var)?;

        let current_midstate_is_correct = MidCircuit::midstate_is_correct(&mid_cur_var, &mid_prev_var, &original_block_var)?;

        let prev_mid_comm_is_correct = MidCircuit::commitment_is_correct(&ck_var, &mid_prev_var, &r_prev_var, &com_prev_var)?;

        let cur_mid_comm_is_correct = MidCircuit::commitment_is_correct(&ck_var, &mid_cur_var, &r_cur_var, &com_cur_var)?;

        // Enforce all constraints are true -- the circuit output
        Boolean::<JubJubBaseField>::
        kary_and(&[
                    bytes_are_partially_equal.clone(), 
                    current_midstate_is_correct.clone(),
                    prev_mid_comm_is_correct.clone(),
                    cur_mid_comm_is_correct.clone()
                  ])?
        .enforce_equal(&Boolean::<JubJubBaseField>::TRUE)?;

        Ok(())
    }
    
}

#[cfg(test)]
pub mod tests {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_r1cs_std::prelude::*;
    use sha256_cf::Block;
    use crate::cp::{pedersen::PedersenCommitmentScheme, JubJubBaseField};

    use super::MidCircuit;
    #[test]
    pub fn partially_equal_bits_gadget() -> () {

        // 0-byte block
        let original_block:Block = [0u8;64].into();
        let mut redacted_block_bytes = original_block.repr();
        redacted_block_bytes[0] = 2;
        redacted_block_bytes[31] = 3;
        redacted_block_bytes[63] = 4;
        let redacted_block:Block = redacted_block_bytes.into();

        // Equality is skipped on redacted bytes
        let mut selector = [true;64];
        selector[0] = false;
        selector[31] = false;
        selector[63] = false;
        
        let cs = ConstraintSystem::<JubJubBaseField>::new_ref();

        let original_block_bytes_var = MidCircuit::allocate_original_block(
            cs.clone(), 
            &original_block
        ).unwrap();

        // Allocate redacted block bytes as witness to skip redacted_block_to_bytes gadget's constraints
        let redacted_block_bytes_var= MidCircuit::allocate_original_block(
            cs.clone(), 
            &redacted_block
        ).unwrap();

        // Directly allocate selector bits.
        let mut selector_var: Vec<Boolean<JubJubBaseField>> = vec![];
        for bit in selector.iter() {
            selector_var.
                push(Boolean::<JubJubBaseField>::new_input(cs.clone(), || Ok(bit)).unwrap());
        }

        let result = MidCircuit::blocks_are_partially_equal(&original_block_bytes_var,&redacted_block_bytes_var,&selector_var).unwrap();
        
        assert_eq!(true,R1CSVar::value(&result).unwrap());
        
        ()
    }

    #[test]
    pub fn redacted_block_to_bytes_gadget() -> () {

        let (pub_inp,_) = 
            MidCircuit::dummy_inputs();

        let block_bytes_correct = pub_inp.redacted_block.repr();

        let cs = ConstraintSystem::<JubJubBaseField>::new_ref();

        let block_fes = MidCircuit::allocate_redacted_block_as_field_elements(&pub_inp, cs.clone()).unwrap();

        let block_bytes_var = MidCircuit::redacted_block_to_bytes(&block_fes).unwrap();

        // Test gadget redacted_block_to_bytes
        for (byte_correct,byte_var) in block_bytes_correct.iter().zip(block_bytes_var.iter()) {
            assert_eq!(*byte_correct,R1CSVar::value(byte_var).unwrap());
        }
        
        ()
    }

    #[test]
    pub fn selector_to_bits_gadget() {
        
        let (pub_inp,_) = 
            MidCircuit::dummy_inputs();

        let selector_bits_correct = pub_inp.selector_block;

        let cs = ConstraintSystem::<JubJubBaseField>::new_ref();

        let selector_fe = MidCircuit::allocate_selector_field_element(&pub_inp,cs.clone()).unwrap();

        let bits_var = 
            MidCircuit::selector_to_bits(&selector_fe).unwrap();

        // Test gadget selector_to_bits
        for (bit_correct,bit_var) in selector_bits_correct.iter().zip(bits_var.iter()){
            assert_eq!(*bit_correct,R1CSVar::value(bit_var).unwrap());
        }

        ()
        
    }

    #[test]
    pub fn mid_circuit_is_satisfiable() -> () {

        let ck = PedersenCommitmentScheme::generate_params().unwrap();
        
        let circuit = MidCircuit::satisfiable_circuit(&ck);

        let cs = ConstraintSystem::<JubJubBaseField>::new_ref();

        let _ = circuit.generate_constraints(cs.clone());

        assert_eq!(true,cs.is_satisfied().unwrap());
        
        ()
    }

    #[test]
    pub fn mid_circuit_is_sound() -> () {
        
        let circuit = unsatisfiable_circuit();
       
        let cs = ConstraintSystem::<JubJubBaseField>::new_ref();

        let _ = circuit.generate_constraints(cs.clone());

        assert_eq!(false,cs.is_satisfied().unwrap());

        ()
    }

    fn unsatisfiable_circuit() -> MidCircuit {

        let (public_input,private_input) = MidCircuit::dummy_inputs();
        MidCircuit
        {
            public_input,
            private_input,
            commitment_key: PedersenCommitmentScheme::generate_params().unwrap()
        }
    }

}