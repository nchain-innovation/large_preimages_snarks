This package contains crates to prove statements about large SHA256 preimages.

- [SHA256 compression function and R1CS gadgets](./crates/sha256-cf/README.md)
- [Partial equality to preimage (peq) snark](./crates/peqpreimage-snark/README.md)
- [Transaction redaction snark](./crates/txredaction-snark/README.md)

These SNARKs along with Merkle proofs can be used to redact data on transactions that are in settled Bitcoin blocks without forks or re-doing proof of work. for more details, see the paper [How to redact the Bitcoin backbone protocol](https://eprint.iacr.org/2024/813.pdf), published in IEEE ICBC 2024. 

## Disclaimer
The code within this repository is intended for research and educational purposes only.

Please note:
- No guarantees are provided regarding the security or the performance of the code.
- Users are responsible for validating the code and understanding its implications before using it in any capacity.
- There may be edge cases causing bugs or unexpected behaviours. Please contact us if you find any bug. 

## License
The code is released under the attached [LICENSE](./LICENSE.txt). If you would like to use it for commercial purposes, please contact research.enquiries@nchain.com.

