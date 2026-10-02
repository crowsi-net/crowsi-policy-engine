# crowsi-policy-engine

Decide whether a verified operation request satisfies an explicit policy.

## What you can do

- Evaluate identity, intent and supplied policy information.
- Return a reproducible allow or deny result.

## Current scope

The engine consumes verified inputs and returns a decision. It does not perform the requested operation.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
