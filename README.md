# E‑D--Crypto

A lightweight command-line utility written in C (or C++) using OpenSSL for encrypting and decrypting files using hybrid encryption (**AES-256-CBC** + **RSA-2048**). Designed for secure file exchange, integrity checking, and compliance-ready deployments.

## ⚙️ Features

* **AES-256-CBC encryption** for bulk file data.
* **RSA-2048 key wrapping** of symmetric keys using **PKCS#1 OAEP padding**.
* Seamless CLI-based **encrypt** / **decrypt** workflows.
* **SHA256 hashing** for integrity verification.
* Supports both binary and hex/base64 formats for encrypted output.
* Detailed error logging via OpenSSL’s `ERR_print_errors_fp()`.

## 🚀 Getting Started

### Prerequisites

Make sure your system includes:

* OpenSSL development libraries (`libssl-dev` / `openssl-devel`)
* Standard C/C++ build tools (`gcc`, `clang`, etc.)

### Build from Source

```sh
git clone https://github.com/28d33/E-D--Crypto.git
cd E-D--Crypto
make        # or use provided build script
```

### Usage

#### Encrypt a File

```sh
./encrypt <input filepath> <output filepath> <public_key.pem>
```

* Encrypts `input filepath` to produce `output filepath` along with metadata (nonce, IV, key file).

#### Decrypt a File

```sh
./decrypt <encrypted filepath> <output filepath> <private_key.pem>
```

* Decrypts the encrypted file using the RSA private key and validates data integrity.

## 🧩 Architecture & Workflow

```
[Plaintext File]
        │
     AES-256 (random key + IV)
        ↓
[Ciphertext File] ──> AES key encrypted via RSA-2048 → stored alongside
        │
Decryption: RSA unwraps key → AES decrypts → SHA256 verification → plaintext output
```

## 🔐 Security Design

* Strong symmetric encryption (AES-256-CBC) for file content.
* Secure key exchange via RSA-2048 + OAEP padding.
* Verifiable integrity using SHA256.
* Minimal external dependencies.

## 📁 Repository Structure

```
.
├── encrypt.c        # AES + RSA encryption utility
├── decrypt.c        # RSA unwrapping + AES decryption utility
├── helpers.c/h      # Shared utility functions (hex <-> bytes, I/O, error handling)
├── Makefile         # Build script for compilation
└── README.md        # Project documentation
```

## 🧪 Example

To encrypt:

```sh
./encrypt secret.txt secret.enc public_key.pem
```

To decrypt:

```sh
./decrypt secret.enc secret_decrypted.txt private_key.pem
```

## 📦 Technologies Used

* **Language**: C (OpenSSL EVP API)
* **Algorithms**: AES‑256‑CBC, RSA‑2048 (OAEP), SHA256
* **Formats**: PEM (public/private keys), binary or hex for ciphertext
* **Platform**: Linux CLI

## 🆘 Error Handling

All OpenSSL errors are printed to `stderr` using:

```c
ERR_print_errors_fp(stderr);
```

Each utility handles cleanup on failure to avoid resource leaks.

## 🔄 Contribution 

Contributions are welcome! Please fork the repository, make changes, and submit a pull request.

---

Feel free to adjust sections like file names, build commands, or features to better match the actual codebase.
