use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{num::{AllocatedNum, Num}, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};

pub trait ToNumGadget<F:PrimeField> {

    /// Converts `self` into an `AllocatedNum` in the contraint system `cs`.
    fn to_num<CS:ConstraintSystem<F>>(&self,cs: &mut CS) -> Result<AllocatedNum<F>,SynthesisError>;

}

impl<F:PrimeField> ToNumGadget<F> for UInt32 {

    fn to_num<CS:ConstraintSystem<F>>(&self,cs: &mut CS) -> Result<AllocatedNum<F>,SynthesisError> {
        
      let mut num = Num::<F>::zero();
      let mut coeff = <F as Field>::ONE;
      for bit in self.clone().into_bits().iter() {    
        num = num.add_bool_with_coeff(CS::one(), bit, coeff);
        coeff = coeff.double();
      }
      
      // Allocate `num` in the constraint system `cs`.
      let num_alloc = AllocatedNum::alloc(
          cs.namespace(|| "allocate num"),
          || {Ok(num.get_value().unwrap())}
          )?;
      
      // Enforce `num` * 1 = `num_alloc`. This ensures the derived Num from 
      // the input UInt32 matches the value in the new allocation.
      cs.enforce(
        || "unpacking constraint",
          |_| num.lc(<F as Field>::ONE),
          |lc| lc + CS::one(),
          |lc| lc + num_alloc.get_variable(),
          );
        
      Ok(num_alloc)
    }
}