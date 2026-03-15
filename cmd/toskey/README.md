toskey
======

toskey is a simple command-line tool for working with TOS keyfiles.


# Usage

### `toskey generate`

Generate a new keyfile.
If you want to use an existing private key to use in the keyfile, it can be 
specified by setting `--privatekey` with the location of the file containing the 
private key (hex-encoded, optional `0x` prefix).
Use `--signer` to choose signer type (default `secp256k1`), supported values:
`schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal`.

Mnemonic flow (BIP39 -> seed -> derived private key/address) is also supported:

- Generate a new mnemonic and derive key at default path:
  - `toskey generate --mnemonic-generate`
- Import from an existing mnemonic:
  - `toskey generate --mnemonic "word1 ... word12"`
- Optional flags:
  - `--hd-path` (default: `m/44'/60'/0'/0/0`)
  - `--mnemonic-passphrase`
  - `--mnemonic-bits` (for `--mnemonic-generate`: 128/160/192/224/256)

Mnemonic derivation currently supports signer types:
- `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal`


### `toskey inspect <keyfile>`

Print various information about the keyfile.
Private key information can be printed by using the `--private` flag;
make sure to use this feature with great caution!


### `toskey signmessage <keyfile> <message/file>`

Sign the message with a keyfile.
It is possible to refer to a file containing the message.
To sign a message contained in a file, use the `--msgfile` flag.


### `toskey verifymessage <address> <signature> <message/file>`

Verify the signature of the message.
It is possible to refer to a file containing the message.
To sign a message contained in a file, use the --msgfile flag.


### `toskey changepassword <keyfile>`

Change the password of a keyfile.
use the `--newpasswordfile` to point to the new password file.

### `toskey priv-keygen [<keyfile>]`

Generate an ElGamal keypair for privacy transactions.
If a keyfile path is provided, the key is also stored as an encrypted `elgamal` keyfile.

Example:

- `toskey priv-keygen`
- `toskey priv-keygen ./priv-key.json`

### `toskey priv-balance <keyfile>`

Decrypt the priv encrypted balance locally from on-chain ciphertext via RPC.
Use `--ct` to decrypt an explicit `commitment||handle` blob instead of calling RPC.
Use `--max-balance` to set the baby-step giant-step search bound.

Example:

- `toskey priv-balance --rpc http://127.0.0.1:8545 ./key.json`
- `toskey priv-balance --ct 0x... --max-balance 100000 ./key.json`

### `toskey priv-shield --amount <n> <keyfile>`

Build priv shield proof locally from the keyfile and submit transaction via `priv_shield`.

Example:

- `toskey priv-shield --rpc http://127.0.0.1:8545 --amount 10 ./key.json`

### `toskey priv-transfer --to <addr> --amount <n> <keyfile>`

Build priv transfer proof locally and submit transaction via `priv_transfer`.

Example:

- `toskey priv-transfer --rpc http://127.0.0.1:8545 --to 0x... --amount 3 ./key.json`

### `toskey priv-unshield --to <addr> --amount <n> <keyfile>`

Build priv unshield proof locally and submit transaction via `priv_unshield`.

Example:

- `toskey priv-unshield --rpc http://127.0.0.1:8545 --to 0x... --amount 2 ./key.json`

Priv tx command notes:

- Requires an `elgamal` keyfile.
- Proof construction uses local cryptography; build `toskey` with CGO + `ed25519c`.
- By default it refuses building when sender has pending tx (`latest nonce != pending nonce`) to avoid stale proof context; use `--allow-pending` only if you understand the risk.


## Passwords

For every command that uses a keyfile, you will be prompted to provide the 
password for decrypting the keyfile.  To avoid this message, it is possible
to pass the password by using the `--passwordfile` flag pointing to a file that
contains the password.

## JSON

In case you need to output the result in a JSON format, you shall by using the `--json` flag.
