
This crate implements SNARKs to prove and verify partial equality to arbitrarily large SHA256 preimages. Namely, to prove statements of the form:

``_The last two bytes of the array `redacted_bytes` are equal to the last two bytes of a preimage of digest `h`''_.

Note that the length of the preimage `original_bytes` and the public `redacted_bytes` can vary, as well as the byte positions that are claimed to be equal (but the positions are the same in both arrays).

## Implementation strategies

This crate follows two strategies to implement the trait [`PeqSnark`](./src/lib.rs#l28).

- A commit-and-prove approach with [Groth16](https://eprint.iacr.org/2016/260). The prover produces as _many_ proofs as SHA56 blocks in the preimage. (Parallelization with [rayon](https://docs.rs/rayon/latest/rayon/) is used to speed up both, proving and verification runtime.).
- An incrementally verified computation (IVC) approach with [Nova](https://eprint.iacr.org/2021/370). This implementation produces a _single_ proof. 

## Arithmetization

### Commit-and-prove strategy
The R1CS for the commit-and-prove circuit [`MidCircuit`](./src/cp/circuit.rs#L187) is built using [arkworks](https://github.com/arkworks-rs) over the scalar field of BLS381. SHA256 midstates are committed with Pedersen hash defined over JubJub. 

**Circuit logic:** // The commitment key `ck` is hard-coded in the circuit's description.
 
* Check that `0 = (redacted_block + original_block)·σ` where `σ` is the selector vector. 
* Check that `mid_cur = Sha256CF(mid_prev,original_block)`
* Check that `com_cur = Pedersen::commit(ck,mid_cur,r_cur)`  
* Check that `com_prev = Pedersen::commit(ck,mid_prev,r_prev)`

### IVC strategy
For the IVC approach, we use [bellpepper](https://github.com/argumentcomputer/bellpepper) to build the R1CS of the [`SelCircuit`](./src/ivc/nova/circuit.rs#L17) over the scalar field of BN254. The accumulated hash is set to Poseidon.

**Circuit logic:**

* Check that `0 = (redacted_block + original_block)·σ` where `σ` is the selector vector
* Check that `mid_cur = SHA256CF(mid_prev,original_block)`
* Check that `a_cur = Poseidon(a_prev,redacted_block,σ)` // Accumulate selector `σ` (and redacted blocks)

### Resulting R1CS constraints
Note that the first two gadgets of the circuits are the same. The overhead is in the SHA256 gadget, as expected. Arithmetization with bellpeper seems to be slightly better.

Gadget | R1CS constraints with arkworks| R1CS constraints with belleper
|----- | ---------------- | -------- 
| SHA256CF | 42415 | 29544
| Partial equality (of blocks) | 2175 | 2624
| Pedersen (twice) | 5102 | N/A
| Accumulated hash| N/A | 3109

## How to use this library

Callers should use either of the two exposed default implementations: [`DefaultCommitandProvePeqScheme`](./src/lib.rs#L11) or [`DefaultIvcPeqScheme`](./src/lib.rs#L18). See the examples folder for more details.

## Commit-and-prove or IVC, which one to use?
It depends on how large are the `original_bytes` (the hash preimage) and the `redacted_bytes`. 

Benchmarks indicates that for sizes of up to ~1KB the commit-and-prove approach yields faster proving time. For larger sizes, the IVC approach outperforms, and the saving gets better the larger the size is, at 128KB is ~30% faster. On the downside, Nova has slow verification. Regarding proof size, the IVC approach is always at ~ 11,4KB. The crossover with the commit-and-prove approach happens at preimage sizes of ~ 4KB. The full benchmarks are [here](../txredaction-snark/benches/128KB.csv).

| Preimage size | Strategy | Prover | Verifier | Proof size
| --- | ----- | -----------------| ---------------- | ----- |
| 128 bytes | Commit-and-prove (Groth16) |~ 1,49 secs |~ 0,012 secs | 752 bytes
| 128 bytes | IVC (Nova) | ~ 2,69 secs | ~ 0,82 secs | ~ 11,6KB
| 512 bytes | Commit-and-prove (Groth16) | ~ 4,9 secs | ~ 0,018 secs | ~ 2KB 
| 512 bytes | IVC (Nova) | ~ 5,81 secs | ~ 2,5 secs | ~ 11,6KB
| 1KB | Commit-and-prove (Groth16) | ~ 8,76 secs |~ 0,034 secs | ~ 3,7KB 
| 1KB | IVC (Nova) | ~ 8,95 secs | ~ 4,61 secs | ~ 11,6KB
| 16KB | Commit-and-prove (Groth16) | ~ 2,5 mins |~ 0,27 secs | ~ 56KB 
| 16KB | IVC (Nova) | ~ 1,8 mins | ~ 1,1 mins | ~ 11,6KB 
| 64KB | Commit-and-prove (Groth16) | ~ 10 mins | ~ 1,21 secs | ~ 224KB 
| 64KB | IVC (Nova) | ~ 7,47 mins | ~ 1,05 mins | ~11,6KB
| 128KB | Commit-and-prove (Groth16) | ~ 24 mins | ~ 2,57 secs | ~448KB 
| 128KB | IVC (Nova) | ~ 16,94 mins | ~ 9,05 mins | ~ 11,6KB



