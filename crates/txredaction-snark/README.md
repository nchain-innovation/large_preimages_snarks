Implementation of SNARKs to prove/verify partial equality to the bytes of a Bitcoin transaction `tx` with a given `txid`.

This crate provides a thin blanket implementation of [`TransactionRedactionSnark`](./src/lib.rs#L18) that leverages any implementation of [`PeqSnark`](./../peqpreimage-snark/src/lib.rs#L28). For more details see crate [peqpreimage-snark](./../peqpreimage-snark/README.md). 

## Benchmarks
The benchmarks reported in the [paper](https://eprint.iacr.org/2024/813.pdf) have been obtained running:

```bash
cargo bench -- --nocapture
```

The commit-and-prove approach uses [Groth16](./../peqpreimage-snark/src/cp/groth16.rs#L43). The IVC approach uses [Nova](./../peqpreimage-snark/src/ivc/nova/mod.rs#L128). See the paper for a comparison of both approaches.