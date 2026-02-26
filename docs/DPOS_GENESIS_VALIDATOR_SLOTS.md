# DPoS Genesis Validator Slots (TOS3)

DPoS reads the active validator set from on-chain storage at
`ValidatorRegistryAddress` (TOS3 =
`0x0000000000000000000000000000000000000000000000000000000000000003`)
via `validator.ReadActiveValidators`.  At every epoch boundary
(`block % epoch == 0`) `FinalizeAndAssemble` calls this function and
embeds the result in the block's `Extra` field.  `VerifyEpochExtra`
then checks that the embedded list matches TOS3 exactly.

If TOS3 is empty at the first epoch boundary the miner silently stalls
(no log, no new blocks).  The fix is to **pre-populate TOS3 in the
genesis `alloc`** so the registry is non-empty from block 0.

## Storage layout

All slots live on the `ValidatorRegistryAddress` account.  Keys are
Keccak-256 hashes; values are 32-byte big-endian words.

| Purpose | Key formula | Value |
|---|---|---|
| validator count | `keccak256("dpos\x00validatorCount")` | `uint64` count, right-aligned |
| list entry `i` | `keccak256("dpos\x00validatorList\x00" \|\| BE8(i))` | address, left-aligned |
| per-addr selfStake | `keccak256(addr[32] \|\| 0x00 \|\| "selfStake")` | `uint256` wei |
| per-addr registered | `keccak256(addr[32] \|\| 0x00 \|\| "registered")` | `0x01` |
| per-addr status | `keccak256(addr[32] \|\| 0x00 \|\| "status")` | `0x01` (Active) |

Notes:
- `BE8(i)` — 8-byte big-endian encoding of the list index.
- Addresses are **32 bytes** in gtos (`common.AddressLength = 32`).
- `status` values: `0 = Inactive`, `1 = Active`.
- The list is **append-only**; withdrawn validators stay in the list
  with `status=Inactive`.

## Generating slots for a new validator set

Use `scripts/gen_genesis_slots/main.go`:

```bash
# Edit the validators slice in main.go to match your addresses, then:
cd ~/gtos
go run ./scripts/gen_genesis_slots/main.go
```

Output is a JSON `"storage"` block ready to paste into genesis `alloc`.

Example output for 3 validators:

```json
"storage": {
  "0xd3d4bbf6...": "0x0000...0003",   // validatorCount = 3
  "0xf7f2d086...": "0x2ebef96d...",   // list[0]
  "0xa67b4fd1...": "0x40f89311...",   // list[1]
  "0xc64b0d15...": "0xb1d2e683...",   // list[2]
  "0x3b93bae4...": "0x0de0b6b3a7640000",  // selfStake[0] = 1 TOS
  "0x34261cf7...": "0x01",            // registered[0]
  "0x0e35a4f1...": "0x01",            // status[0] = Active
  ...
}
```

## Embedding in genesis

Add the TOS3 account to the `alloc` section of your genesis JSON:

```json
"alloc": {
  "<validator-addr-1>": { "balance": "0x..." },
  "<validator-addr-2>": { "balance": "0x..." },
  "<validator-addr-3>": { "balance": "0x..." },
  "0x0000000000000000000000000000000000000000000000000000000000000003": {
    "balance": "0x0",
    "storage": {
      <paste output from gen_genesis_slots here>
    }
  }
}
```

Then re-initialize all nodes:

```bash
sudo systemctl stop gtos-node1 gtos-node2 gtos-node3
for i in 1 2 3; do
  rm -rf /data/gtos/node$i/gtos/chaindata /data/gtos/node$i/gtos/triecache
done
for i in 1 2 3; do
  ./build/bin/gtos init --datadir /data/gtos/node$i /data/gtos/genesis_testnet_3vals.json
done
sudo systemctl start gtos-node1 gtos-node2 gtos-node3
```

## Verifying after init

Check that `validatorCount` is non-zero on the genesis state:

```bash
curl -s -X POST http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","method":"tos_getStorageAt",
    "params":[
      "0x0000000000000000000000000000000000000000000000000000000000000003",
      "0xd3d4bbf6c70cd62303384d0f5f650a621550d6fce3463c8a5145f70373758537",
      "latest"
    ],"id":1
  }' | python3 -c "import sys,json; print('validatorCount:', int(json.load(sys.stdin)['result'],16))"
```

Expected: `validatorCount: 3` (or however many validators were registered).

## What happens at the epoch boundary

When `block % epoch == 0`:

1. `FinalizeAndAssemble` calls `ReadActiveValidators(statedb, maxValidators)`.
2. Validators are sorted: first by stake descending, then by address
   ascending as tiebreak, then truncated to `maxValidators`.
3. The resulting address list is embedded in `header.Extra` (between the
   32-byte vanity prefix and the 65-byte seal suffix).
4. On import, `VerifyEpochExtra` re-reads TOS3 from the post-execution
   state and asserts the Extra list matches exactly.

Because the genesis alloc pre-seeds TOS3, step 1 succeeds from the very
first epoch block without requiring any `VALIDATOR_REGISTER` transactions
to have been sent beforehand.
