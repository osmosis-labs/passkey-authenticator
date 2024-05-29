# Passkey Authenticator

Passkey Authenticator is a CosmWasm [authenticator](https://github.com/osmosis-labs/osmosis/blob/main/x/smart-account/README.md) that allows signing transactions using secp256r1.

## Background 

Over the years, secp256k1 has become the de facto standard for many cryptocurrencies and blockchain platforms. It was originally chosen by Satoshi Nakamoto for its efficiency and security properties and various other reasons. One of the key advantages of secp256k1 is its resistance to known attacks. Such as Pollard's rho algorithm for solving the elliptic curve discrete logarithm problem (ECDLP). Its proven track record in Bitcoin and its compatibility with existing cryptographic libraries and hardware implementations gave secp256k1 widespread adoption. 
However, as things evolves, secp256r1 had become an industry standard and widely adopted outside of crypto. The Osmosis passkey authenticator feature represents an effort to provide an alternative option for transaction signing while maintaining a high level of security.

secp256r1 is considered secure elliptic curves in the same way secp256k1 does. They have a similar security level, providing around 128 bits of security, which is currently (2024) considered sufficient for most applications.

## Overview

Each passkey authenticator must have [PasskeyParams](./contracts/passkey/src/passkey/params.rs) as authenticator params. This is act as a parameter for each specific instance of the authenticator and stored in the module state. It will be passed along to to its hooks and can be used to enforce the passkey verification.

Other global configurations and states are stored in the [contract state](./contracts/passkey/src/state.rs).

The authenticator verifies the transaction p256 signature. If the transaction signature does not verify the transaction will be rejected. Here is the breakdown:

TODO: please finish

## Development

### Pre-requisites

- [Rust](https://www.rust-lang.org/)
- [Go](https://golang.org/) (for running integration tests & localosmosis)
- [CosmWasm Setup](https://book.cosmwasm.com/setting-up-env.html)
- [Beaker](https://github.com/osmosis-labs/beaker)
- [Docker](https://www.docker.com/)

### Build

Building wasm binary for testing:

```sh
cd contract/passkey
cargo wasm
```

Note that the flag `--no-wasm-opt` is used to disable wasm-opt optimization. This is useful for debugging and testing and small enough since debug symbols are stripped, it's not recommended for production. Omit this flag for production build.

Output wasm bytecode is stored at `target/wasm32-unknown-unknown/release/passkey_authenticator.wasm`.

### Testing

This repo has automated unit testing as well as integration tests using [`test-tube`](https://github.com/osmosis-labs/test-tube). `test-tube` requires the above artifacts to be built in order to run the tests.
