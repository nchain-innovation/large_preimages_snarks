Implementation of SNARKs to prove/verify partial equality to the bytes of a Bitcoin transaction `tx` with a given `txid`. These SNARKs along with Merkle proofs can be used to redact data on transactions that are in settled Bitcoin blocks without forks or re-doing proof of work. for more details, see the paper [How to redact the Bitcoin backbone protocol](https://eprint.iacr.org/2024/813.pdf), published in IEEE ICBC 2024. 

This crate provides a thin blanket implementation of [`TransactionRedactionSnark`](./src/lib.rs#L18) that leverages any implementation of [`PeqSnark`](./../peqpreimage-snark/src/lib.rs#L27). For more details see crate [peqpreimage-snark](./../peqpreimage-snark/README.md). 

## Benchmarks
The benchmarks reported in the paper mentioned above have been obtained running:

```bash
cargo bench -- --nocapture
```

The commit-and-prove approach uses [Groth16](./../peqpreimage-snark/src/mid/groth16.rs#L43). The IVC approach uses [Nova](./../peqpreimage-snark/src/sel/nova/mod.rs#L128). See the paper above for a comparison of both approaches.