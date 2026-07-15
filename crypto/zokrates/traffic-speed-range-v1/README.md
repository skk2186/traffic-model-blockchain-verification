# traffic-speed-range-v1 ZoKrates circuit

This circuit proves that a private traffic speed is inside a public inclusive range:

```text
minSpeed <= speed <= maxSpeed
```

Inputs are ordered as follows:

1. `speed`: private `u32`
2. `minSpeed`: public `u32`
3. `maxSpeed`: public `u32`

The checked fixture uses `speed=60`, `minSpeed=30`, and `maxSpeed=80`.

## Build and generate fixtures

Run from the repository root with Windows PowerShell 5.1 or newer:

```powershell
& '.\crypto\zokrates\traffic-speed-range-v1\scripts\build.ps1'
& '.\crypto\zokrates\traffic-speed-range-v1\scripts\generate-valid-proof.ps1'
& '.\crypto\zokrates\traffic-speed-range-v1\scripts\verify-proof.ps1'
```

`build.ps1` refuses to replace existing setup keys unless `-Force` is supplied explicitly. The setup uses ZoKrates 0.8.7 with curve `bn128`, proving scheme `g16`, and backend `ark`.

Generated runtime artifacts are placed in `runtime/zkp/traffic-speed-range-v1/`. This directory is ignored because it contains the proving key, witness, generated proofs, and other runtime artifacts.

The public `verification.key` is produced by `zokrates setup` from the compiled circuit and copied to `keys/verification.key`. It is safe to distribute to verifiers, but it must remain paired with the exact circuit, curve, proving scheme, and backend that produced it. The later Java adapter can load this public key through a configured key registry; it must not load `proving.key`.

ZoKrates 0.8.7 returns exit code `0` for both `PASSED` and cryptographic `FAILED` results. `verify-proof.ps1` therefore requires both a zero exit code and an exact `PASSED` output line.

## Fixtures

- `fixtures/valid/proof.json`: native ZoKrates proof generated from the valid witness.
- `fixtures/valid/public-signals.json`: the public `inputs` copied from that proof.
- `fixtures/invalid-public-input/proof.json`: a copy whose first public input is modified after proof generation.
- `fixtures/invalid-public-input/public-signals.json`: public inputs corresponding to the modified negative fixture.

The proof files retain the native ZoKrates JSON structure. They are not converted to snarkjs field names.
