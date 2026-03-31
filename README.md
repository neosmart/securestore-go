[![Go Reference](https://pkg.go.dev/badge/github.com/neosmart/securestore-go.svg)](https://pkg.go.dev/github.com/neosmart/securestore-go) [![Go project version](https://badge.fury.io/go/github.com%2Fneosmart%2Fsecurestore-go.svg)](https://pkg.go.dev/github.com/neosmart/securestore-go)

# SecureStore Go library

This repository/package houses a Go implementation of the cross-platform, language-agnostic [SecureStore secrets specification](https://neosmart.net/SecureStore). In particular, this library may be used for interacting with [SecureStore](https://github.com/neosmart/securestore-rs) secrets containers, providing an easy-to-use and idiomatic interface for loading SecureStore containers and decrypting/retrieving secrets from within your existing PHP code.

## Usage

_This Go library is largely intended to be used alongside one of the SecureStore cli companion apps, used to create SecureStore values and manage (add/remove/update) the secrets stored therein. In this example, we'll be using the [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) cli utility to create a new store._

### Creating a secrets vault

Typical SecureStore usage begins by creating a new SecureStore "vault" (an encrypted secrets container) that will store the credentials (usually both usernames and passwords) that your app will need. Begin by compiling or downloading and installing a copy of [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient), the SecureStore companion cli.

While you can compile it yourself or manually download [pre-built binaries for your platform](https://github.com/neosmart/securestore-rs/releases), you might find it easiest to just install it with `npm`:

```bash
~> npm install --global ssclient
```

after which you can proceed with the following steps:

```bash
~> mkdir secure/
~> cd secure/
~> ssclient create --export-key secrets.key
Password: ************
Confirm Password: ************

# Now you can use `ssclient -p` with your password or
# `ssclient -k secrets.key` to encrypt/decrypt with
# the same keys.
```

### Adding secrets

Secrets may be added with your password or the equivalent encryption key file, and may be specified in-line as arguments to `ssclient` or more securely at a prompt by omitting the value when calling `ssclient create`:

```bash
# ssclient defaults to password-based decryption:
~> ssclient set aws:s3:accessId AKIAV4EXAMPLE7QWERT
Password: *********
```

similarly:

```bash
# Use `-k secrets.key` to load the encryption key and
# skip the prompt for the vault password:
~> ssclient -k secrets.key set aws:s3:accessKey
Value: v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j
```

### Retrieving secrets

Secrets can be retrieved [at the commandline with `ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) or programmatically with a SecureStore library [for your development language or framework of choice](https://neosmart.net/SecureStore).

This library contains the golang implementation of the SecureStore protocol. The implementation is currently fully contained within the single `securestore.go` source file with minimal dependencies (only a single unavoidable dependency on the `x/crypto` module), and published to its own git repo for friendly consumption with `go get`:

```sh
go get github.com/neosmart/securestore-go
```

```go
// sman, err := securestore.LoadWithPassword("secure/secrets.json", "sUperDuPERsecret")
sman, err := securestore.LoadWithKeyFile("secure/secrets.json", "secure/secrets.key")
if err != nil {
    log.Fatalf("Failed to load SecureStore vault: %v", err)
}

// Retrieve and decrypt a specific secret
val, err := sman.Get("aws:s3:accessKey")
if err != nil {
    log.Fatalf("Error retrieving s3 access key: %v", err)
}
fmt.Printf("Decrypted secret: %s\n", val)

// List all available keys in the vault
allKeys := sman.Keys()
fmt.Printf("Vault contains %d keys: %v\n", len(allKeys), allKeys)
```

While it is **strongly recommended** to only load secrets programmatically with the encryption key with `LoadWithKeyFile()` so as to avoid hard-coding any secrets in your code by specifying the path to the encryption key created by `ssclient` via the `--export-key` flag or top-level `ssclient export-key` command, an alternative `securestore.LoadWithPassword("path/to/secrets.json", "your-password")` interface is also available; this can be used if you're developing an interactive tool using SecureStore, for example.

## API overview

The `SecureStore` library provides a high-level interface for decrypting and accessing secrets stored in SecureStore v3 vaults.

### SecretsManager
The `SecretsManager` is the primary interface for interacting with a decrypted vault.

#### Initialization
These functions load a vault file from disk, initialize the manager, and verify the vault's integrity using an internal sentinel.

| Function | Description |
|:---|:---|
| **`Load(path, keySource)`** | Loads a vault using a pre-configured `KeySource` (see below). |
| **`LoadWithPassword(path, password)`** | Convenience method to load a vault using a plaintext password string. |
| **`LoadWithKeyFile(path, keyPath)`** | Convenience method to load a vault using a key file located on disk. |
| **`LoadWithKey(path, key)`** | Convenience method to load a vault using an already loaded key (as a byte slice). |

#### Methods
Once initialized, use these methods to interact with the loaded secrets:

| Method | Description |
|:---|:---|
| **`Get(name string) (string, error)`** | Retrieves a secret by its key/name. Returns `ErrSecretNotFound` if the key is missing. |
| **`Keys() []string`** | Returns a slice with names (keys) of all secrets in the vault. |

---

### KeySource
The `KeySource` type abstracts over the type of credentials used to unlock a vault.

| Method | Description |
|:---|:---|
| **`NewKeySourceFromPassword(password string)`** | Creates a source that derives decryption keys from a password using PBKDF2-SHA1. |
| **`NewKeySourceFromFile(path string)`** | Loads a SecureStore decryption key from the provided path. |
| **`NewKeySourceFromBytes(key []byte)`** | Creates a source from a SecureStore encryption key loaded into a byte slice. |
