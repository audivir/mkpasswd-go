# mkpasswd-go

`mkpasswd-go` is a Go implementation of the classic `mkpasswd` utility (originally part of the Debian `whois` package, maintained by Marco d'Itri).

It wraps the system's `crypt(3)` library to generate cryptographically strong hashed passwords.
It supports modern hashing algorithms like **yescrypt**, **bcrypt**, and **SHA-512**.

## Prerequisites

This tool uses CGo to interface with `libxcrypt`. You must have the development headers installed.

**Homebrew (macOS):**

```bash
brew install libxcrypt
```

**Debian/Ubuntu:**

```bash
sudo apt install libcrypt-dev
```

**Fedora/RHEL:**

```bash
sudo dnf install libxcrypt-devel

```

**Alpine:**

```bash
apk add libxcrypt-dev

```

## Installation

```bash
# on macOS
# export PKG_CONFIG_PATH=/usr/local/opt/libxcrypt/lib/pkgconfig

go install github.com/audivir/mkpasswd-go@latest

```

Or build manually:

```bash
# on macOS
# export PKG_CONFIG_PATH=/usr/local/opt/libxcrypt/lib/pkgconfig

git clone https://github.com/audivir/mkpasswd-go
cd mkpasswd-go
go build .

```

## Usage

```bash
# Basic usage (defaults to SHA-512)
mkpasswd-go

# Interactive mode (prompts for password)
mkpasswd-go -m sha-256

# Read from Stdin
echo -n "mypassword" | mkpasswd-go -s

# Specific algorithm and cost
mkpasswd-go -m yescrypt -R 12

# Help
mkpasswd-go --help
```

### Supported Methods

- `yescrypt`
- `gost-yescrypt`
- `scrypt`
- `bcrypt` (`bcrypt-a`, `bf`)
- `sha512crypt` (`sha-512`, default)
- `sha256crypt` (`sha-256`)
- `sunmd5`
- `md5crypt` (`md5`)
- `bsdicrypt` (legacy)
- `descrypt` (`des`, legacy)
- `nt` (legacy)

## Acknowledgments

This project is a Go port based on the logic found in `mkpasswd.c` from the [rfc1036/whois](https://github.com/rfc1036/whois) repository, maintained by Marco d'Itri.

## License

This project is licensed under the **GPL-2.0** License to maintain compatibility with the upstream source code. See the `LICENSE` file for details.
