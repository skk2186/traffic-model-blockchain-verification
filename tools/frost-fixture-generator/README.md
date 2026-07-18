# Dynamic FROST fixture generator

This test-only tool executes real FROST(Ed25519, SHA-512) cryptography for a
caller-selected `t-of-n` policy:

1. trusted-dealer key splitting for `n` logical signers;
2. round-one nonce commitments for the selected participants;
3. round-two signature-share generation;
4. coordinator aggregation and group-public-key verification.

Example for 6-of-10:

```powershell
$businessId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('traffic-dynamic-6of10'))
$message = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('traffic speed range approved'))

.\target\release\wecross-frost-fixture.exe `
  --policy-id dynamic-frost-6of10-example `
  --business-id-base64 $businessId `
  --message-base64 $message `
  --threshold 6 `
  --total-nodes 10 `
  --participants 1,2,4,5,6,7
```

Build with a current Rust toolchain:

```powershell
cargo build --release
```

The program never returns or writes private shares. All shares exist only in
the generator process and are dropped when it exits. This makes the endpoint
suitable for local cryptographic integration tests, not production custody.
Production deployments must run DKG and the two FROST rounds across independent
authenticated signer services, with one share held by each signer node.
