# Using crowsi-policy-engine

Decide whether a verified operation request satisfies an explicit policy.

## Before you start

The engine consumes verified inputs and returns a decision. It does not perform the requested operation.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Evaluate identity, intent and supplied policy information.
- Return a reproducible allow or deny result.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
