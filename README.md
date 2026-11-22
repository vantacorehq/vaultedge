# vaultedge

Service for rotating secrets and issuing short-lived signed tokens.

Pure Rust. Zero dependencies.

Logical evolution of vantacorehq/envguard and vantacorehq/anchor.

## What it solves

- Long-lived keys living in every microservice
- No audit of who requested a secret
- Impossible to revoke a compromised token instantly
- Secrets checked only at build time, not at runtime

## Features

- Issue short-lived HMAC tokens (seconds to minutes)
- Instant revoke by token ID or subject
- Full audit log of every issue / verify / revoke
- Key rotation without downtime
- Bridge-style API for KMS or local key hierarchy
- Embeddable or standalone

## Usage

```rust
use vaultedge::{Vault, TokenRequest};

let mut vault = Vault::new(b"root-key-material");

let req = TokenRequest {
    subject: "payment-service",
    ttl_secs: 60,
    scopes: &["read:ledger"],
};

let token = vault.issue(&req).expect("issued");

// Later, in another service
match vault.verify(&token.token) {
    Ok(claims) => {
        // authorized
    }
    Err(_) => {
        // rejected or revoked
    }
}

vault.revoke_subject("payment-service");
```

## Commercial

Centralized short-lived key issuance with audit and revoke: $1200–$3500.

## License

MIT
