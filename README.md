# msc-bbs-anonymous-credentials

This repository implements BBS++ anonymous credentials using the BLS12-381 curve in Go. It provides functionality for issuing, presenting, and verifying credentials with selective disclosure and zero-knowledge proofs.

## Features

- **Credential Issuance:** Generate BBS++ signatures over user attributes.
- **Selective Disclosure:** Present only selected attributes while keeping others hidden.
- **Zero-Knowledge Proofs:** Prove possession of a valid credential without revealing the signature or hidden attributes.
- **Verification:** Verify proofs and ensure credentials were issued by a trusted authority.
- **Benchmarks:** Measure performance and proof sizes for different attribute vector lengths.

## Structure

- `models/` – Data structures for keys, signatures, and proofs.
- `setup/` – System setup and key generation.
- `issue/` – Credential issuance (signing).
- `presentation/` – Presentation protocol and proof generation.
- `verify/` – Proof verification logic.
- `utils/` – Cryptographic utilities and helpers.
- `experiments/` – Scripts for benchmarking and experiments.

## Usage

### Prerequisites

- Go 1.20+
- [Cloudflare CIRCL library](https://github.com/cloudflare/circl)
- [Standalone BBS++ package](https://github.com/aniagut/msc-bbs-plus-plus)

### Build & Test

```sh
go build ./...
go test ./...
```

### Example

```go
import (
    "github.com/aniagut/msc-bbs-anonymous-credentials/models"
    "github.com/aniagut/msc-bbs-anonymous-credentials/setup"
    "github.com/aniagut/msc-bbs-anonymous-credentials/issue"
    "github.com/aniagut/msc-bbs-anonymous-credentials/presentation"
    "github.com/aniagut/msc-bbs-anonymous-credentials/verify"
)

// Setup system parameters and keys
setupResult, _ := setup.Setup(l)

// Issue a credential (signature) for user attributes
signature, _ := issue.Issue(attributes, setupResult.PublicParameters, setupResult.SecretKey)

// Present a credential with selective disclosure
proof, _ := presentation.Presentation(attributes, signature, revealedIndices, setupResult.PublicParameters, nonce)

// Verify the proof
valid, _ := verify.Verify(proof, nonce, revealedAttributes, revealedIndices, setupResult.PublicParameters, setupResult.PublicKey)
```

## Experiments

To run performance experiments and measure proof sizes:

```sh
go run experiments/experiments_presentation.go
```

Results are saved in `experiments/results/`.

## License

MIT License

---