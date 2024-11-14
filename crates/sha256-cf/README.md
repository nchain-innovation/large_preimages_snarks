This crate exposes the [RustCrypto SHA256](https://crates.io/crates/sha2/0.10.8) compression function as an stateless function. It also provides R1CS gadgets to prove/verify statements in zero-knowledge.


# Example
**Note**: Low-level computation of a SHA256 digest. It is responsability of the caller to pad the bytes and iterate the compression function as many times as needed.

Start importing the compression function:

```rust
use sha256_cf::Sha256CF;
```

First, let's pad e.g. 56 bytes, which results in two SHA256 [`Block`](./src/lib.rs#L96) 

```rust
let bytes = [0u8;56];
let padded_blocks = Sha256CF::pad_last_block_bytes(&bytes, 56*8);
```

The output `Block`s are ready to be hashed. Let's calculate the bytes digest iterating the compression function:

```rust
use sha256_cf::Digest;

let init_state = SHA256::get_iv();
let midstate = Sha256CF::apply_compression_function(&init_state, &padded_blocks[0]);
let digest:Digest = Sha256CF::apply_compression_function(&midstate, &padded_blocks[1]).into();
```

The calculated [`Digest`](./src/lib.rs#L206) matches the one from RustCrypto:

```rust
use sha2::Sha256; // RustCrypto.

let rust_crypto_digest_bytes = <Sha256 as sha2::Digest>::digest(bytes);

assert_eq!(*digest.to_be_bytes(),*rust_crypto_digest_bytes);
```