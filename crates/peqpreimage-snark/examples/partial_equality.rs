// Run with `cargo run --release --example partial_equality`.
use sha2::Digest;
use peqpreimage_snark::{PeqSnark,DefaultCommitandProvePeqScheme};

fn main() {

    // Data.
    let original_bytes = vec![0u8;65]; // Two blocks.
    let mut redacted_bytes = original_bytes.clone();
    redacted_bytes.pop(); // Change last two bytes.
    redacted_bytes.pop();
    redacted_bytes.push(1); 
    redacted_bytes.push(2);
    println!("{}",format!("original bytes: {:?}", original_bytes));
    println!("{}",format!("redacted bytes: {:?}", redacted_bytes));

    // Hash with RustCrypto sha256 hasher.
    let original_digest = sha2::Sha256::digest(&original_bytes).to_vec();

    // Generate the prover and verifier keys.
    println!("Generating prover/verifier keys...");
    let (pk,vk) = <DefaultCommitandProvePeqScheme as PeqSnark>::setup().unwrap();


    // Prove partial equality of the original and redacted bytes. 
    println!("Proving partial equality (equality is enforced in all but last two bytes)...");
    let mut selector = vec![true;63];
    selector.push(false);
    selector.push(false);
    let proof = <DefaultCommitandProvePeqScheme as PeqSnark>::prove(
        &pk, 
        &redacted_bytes, 
        &selector, 
        &original_digest,
        &original_bytes).unwrap();

    // Verify the proof using the original digest and the bytes where equality 
    // must be enforced (given in `selector`).
    println!("Verifying proof with right digest and correct redaction...");
    let mut is_valid = <DefaultCommitandProvePeqScheme as PeqSnark>::verify(
        &vk, 
        &redacted_bytes, 
        &selector, 
        &original_digest, 
        &proof).unwrap();

    assert!(is_valid);
    println!("\tproof is valid.");

    // A correct redaction with a different digest does not verify. 
    println!("Verifying using a different digest...");
    is_valid = <DefaultCommitandProvePeqScheme as PeqSnark>::verify(
        &vk, 
        &redacted_bytes, 
        &selector, 
        &[0u8;32], 
        &proof).unwrap();

    assert!(!is_valid);
    println!("\tproof is not valid.");


    // An incorrect redaction does not verify: e.g we claim the last byte 
    // of `redacted_bytes` wasn't changed.
    selector.pop();
    selector.push(true);
    
    println!("Verifying proof for the fake statement `all but last byte are equal'...");
    let is_valid = <DefaultCommitandProvePeqScheme as PeqSnark>::verify(
        &vk, 
        &redacted_bytes, 
        &selector, 
        &original_digest, 
        &proof).unwrap();

    assert!(!is_valid);
    println!("\tproof is not valid");

}