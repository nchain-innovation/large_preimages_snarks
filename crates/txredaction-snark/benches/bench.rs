// Run with `cargo bench -- --nocapture`
use peqpreimage_snark::NumberConstraints;
use txredaction_snark::{TransactionRedactionSnark,DefaultCommitandProveTxredactionScheme, DefaultIvcTxredactionScheme};

use std::{thread::sleep, time::{Duration, Instant}};

use sha2::Digest;

const SETUP_REPEATS: u32 = 1;
const PROVE_REPEATS: u32 = 1;
const VERIFY_REPEATS: u32 = 1;
// Benchmark with up to MAX_BLOCK*64 bytes.
// 1KB of data: MAX_BLOCK = 16. 
const MAX_BLOCKS: usize = 2048;

macro_rules! print_constraints {
    ($snark:ty) => {
        println!("# Gadget constraints");
        let map = <$snark as NumberConstraints>::print();
        for (gadget, constraints_num) in map.iter() {
            println!("{gadget}:; {constraints_num}");
        }
    }
}

macro_rules! bench_peq_snark {
    ($scheme:ident, $snark:ty) => {

    println!("# Runtime, proof size and input size");

    // Setup
    let setup_start = Instant::now();
    let mut setup_time_avg = Duration::new(0, 0);
    let (pk,vk) = <$snark as TransactionRedactionSnark>::setup().unwrap();
    sleep(Duration::new(1, 0));
    for _i in 1..SETUP_REPEATS {
            let _ = <$snark as TransactionRedactionSnark>::setup().unwrap();
        }
    setup_time_avg += setup_start.elapsed() / SETUP_REPEATS;
    let setup_time_avg_seconds = duration_as_seconds(&setup_time_avg);

    println!("Setup:; {:?}",setup_time_avg_seconds);

    // Prover
    
    println!("scheme; preimage (bytes);prover (s);verifier (s);proof (bytes);public input (bytes)");
    
    
    for blocks in benchmark_range(MAX_BLOCKS).into_iter() {

        let (
            original_bytes,
            redacted_bytes,
            selector,
            original_txid
        ) = generate_transactions_bytes_and_selector(blocks);
       
        let prove_start = Instant::now();
        let mut prove_time_avg = Duration::new(0, 0);
        let proof = <$snark as TransactionRedactionSnark>::prove(
            &pk, 
            &redacted_bytes, 
            &selector,
            &original_txid, 
            &original_bytes)
            .unwrap();

        for _i in 1..PROVE_REPEATS {
                let _ = <$snark as TransactionRedactionSnark>::prove(
                    &pk, 
                    &redacted_bytes, 
                    &selector, 
                    &original_txid,
                    &original_bytes);
            }
        prove_time_avg += prove_start.elapsed() / PROVE_REPEATS;
        let prove_time_avg_seconds = duration_as_seconds(&prove_time_avg);
        
        // Verifier
        let original_txid:[u8;32] = original_txid.clone().try_into().unwrap();

        let verify_start = Instant::now();
        let mut verify_time_avg = Duration::new(0, 0);
        let is_valid = <$snark as TransactionRedactionSnark>::verify(
            &vk, 
            &redacted_bytes, 
            &selector, 
            &original_txid, 
            &proof).unwrap();

            for _i in 1..VERIFY_REPEATS {
                let _ = <$snark as TransactionRedactionSnark>::verify(
                    &vk, 
                    &redacted_bytes, 
                    &selector, 
                    &original_txid, 
                    &proof);
            }
        verify_time_avg += verify_start.elapsed() / VERIFY_REPEATS;
        let verify_time_avg_seconds = duration_as_seconds(&verify_time_avg);
        assert!(is_valid);

        // Print results
        println!("{};{:?};{:?};{:?};{:?};{:?}",
                $scheme,
                blocks*64,
                prove_time_avg_seconds,
                verify_time_avg_seconds,
                proof.serialized_proof_size(),
                redacted_bytes.len()+selector.len()+original_txid.len()
        );
    }
        
    };
}

// Let's benchmark stuff.
fn main() {

    println!("Benchmarking with preimages of up to:; {} bytes",MAX_BLOCKS*64);
    println!("Setup runtime samples:; {}",SETUP_REPEATS);
    println!("Prover runtime samples:; {}",PROVE_REPEATS);
    println!("Verifer runtime samples:; {}",VERIFY_REPEATS);

    println!("COMMIT AND PROVE APPROACH (commit to midstates)");
    let scheme = "Groth16";
    print_constraints!(DefaultCommitandProveTxredactionScheme);
    bench_peq_snark!(scheme,DefaultCommitandProveTxredactionScheme);

    println!("IVC APPROACH (commit to selector)");
    let scheme = "Nova";
    print_constraints!(DefaultIvcTxredactionScheme);
    bench_peq_snark!(scheme,DefaultIvcTxredactionScheme);

}

fn duration_as_seconds(duration: &Duration) -> f64 {
    duration.subsec_nanos() as f64 / 1_000_000_000f64 + (duration.as_secs() as f64)
}

// Generate dummy transactions and selector with `number_blocks` blocks, 
// i.e. with 64*`number_blocks` bytes
fn generate_transactions_bytes_and_selector(number_blocks: usize) 
-> (Vec<u8>,Vec<u8>,Vec<bool>,Vec<u8>) {

    let bytes = vec![0u8;number_blocks*64];
    let selector = vec![true;number_blocks*64];
   
    let original_txid =sha2::Sha256::digest(
        sha2::Sha256::digest(&bytes)
    ).to_vec();

    (bytes.clone(),bytes,selector,original_txid)
}

fn benchmark_range(max_block: usize) -> Vec<usize> {
    
    let mut range = Vec::new();

    for i in 1..std::cmp::min(max_block,16) { range.push(i) }

    if 16 <= max_block {

        for i in 1..(std::ops::Div::div(max_block, 16)+1) { range.push(16*i) }
    }

    range
}