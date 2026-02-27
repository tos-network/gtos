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

### `toskey uno-balance <keyfile>`

Decrypt the UNO encrypted balance locally from on-chain ciphertext via RPC.

Example:

- `toskey uno-balance --rpc http://127.0.0.1:8545 ./key.json`

### `toskey uno-shield --amount <n> <keyfile>`

Build UNO shield proof locally from the keyfile and submit transaction via `tos_unoShield`.

Example:

- `toskey uno-shield --rpc http://127.0.0.1:8545 --amount 10 ./key.json`

### `toskey uno-transfer --to <addr> --amount <n> <keyfile>`

Build UNO transfer proof locally and submit transaction via `tos_unoTransfer`.

Example:

- `toskey uno-transfer --rpc http://127.0.0.1:8545 --to 0x... --amount 3 ./key.json`

### `toskey uno-unshield --to <addr> --amount <n> <keyfile>`

Build UNO unshield proof locally and submit transaction via `tos_unoUnshield`.

Example:

- `toskey uno-unshield --rpc http://127.0.0.1:8545 --to 0x... --amount 2 ./key.json`

UNO tx command notes:

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
