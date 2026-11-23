# vaultedge

**Secrets rotation + short-lived signed tokens.**

HMAC / JWT-style · Instant revoke · Full audit · Pure Rust · Zero dependencies

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## The problem

- Long-lived keys living in every microservice
- No audit of who requested a secret
- Impossible to revoke a compromised token instantly
- Secrets checked only at build time

## Features

| Feature | Description |
|---------|-------------|
| Short-lived tokens | TTL from seconds to minutes |
| Instant revoke | By token ID or subject |
| Full audit log | Every issue / verify / revoke |
| Key rotation | Without downtime |
| Embeddable | Library or standalone service |
| Zero dependencies | Only `std` |

## Quick start

```toml
[dependencies]
vaultedge = { git = "https://github.com/vantacorehq/vaultedge" }
```

```rust
use vaultedge::{Vault, TokenRequest};

fn main() {
    let mut vault = Vault::new(b"root-key-material");

    let req = TokenRequest {
        subject: "payment-service",
        ttl_secs: 60,
        scopes: &["read:ledger"],
    };

    let token = vault.issue(&req).expect("issued");

    match vault.verify(&token.token) {
        Ok(claims) => println!("authorized: {:?}", claims),
        Err(_) => println!("rejected or revoked"),
    }

    vault.revoke_subject("payment-service");
}
```

## License

MIT
