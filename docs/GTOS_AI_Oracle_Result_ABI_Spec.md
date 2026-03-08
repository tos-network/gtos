# GTOS AI Oracle Result ABI Specification
## Including `.abi` Interface Draft for Prediction Markets

**Status:** Draft  
**Target chain:** GTOS  
**Language:** English  
**Scope:** Canonical result ABI for GTOS AI Oracle / OracleHub, especially for Polymarket-style event markets and Kalshi-style scalar markets.

---

## 1. Purpose

This document defines the canonical result ABI for GTOS AI Oracle.

The ABI is designed so that:

- off-chain AI systems may observe, summarize, classify, and normalize reality
- on-chain consumers receive compact, deterministic, comparable outputs
- prediction markets can settle on bounded result types
- OracleHub can aggregate, challenge, slash, and finalize reports safely

The ABI must avoid free-form text settlement.  
Every result must reduce to a small structured object.

---

## 2. Design Principles

1. **Canonical over narrative**  
   Free-form reasoning may exist off-chain but must not be part of the settlement object.

2. **Cross-market minimalism**  
   A single ABI family should support event, enum, scalar, range, and invalid outcomes.

3. **Deterministic comparability**  
   Two result payloads must be comparable by hash and equality rules.

4. **Proof compatibility**  
   The ABI must be stable enough for commit/reveal, evidence-root binding, and Phase III proof systems.

---

## 3. Core Result Types

```text
RESULT_TYPE_BINARY = 1
RESULT_TYPE_ENUM   = 2
RESULT_TYPE_SCALAR = 3
RESULT_TYPE_RANGE  = 4
RESULT_TYPE_STATUS = 5
```

### Recommended status codes

```text
STATUS_PENDING       = 0
STATUS_FINAL         = 1
STATUS_INVALID       = 2
STATUS_UNRESOLVABLE  = 3
STATUS_DISPUTED      = 4
STATUS_REVERTED      = 5
```

---

## 4. Common Header

Every canonical oracle result begins with the same logical header.

```text
OracleResultHeader {
  uint8   version
  bytes32 query_id
  bytes32 market_id
  uint8   result_type
  uint8   status
  uint8   proof_mode
  uint64  finalized_at
  uint16  confidence_bps
  bytes32 policy_hash
  bytes32 evidence_root
  bytes32 source_proofs_root
}
```

### Notes

- `version`: ABI version
- `query_id`: canonical OracleHub query ID
- `market_id`: application-level market ID
- `result_type`: binary / enum / scalar / range / status
- `status`: finalization status
- `proof_mode`: selected proof mode
- `finalized_at`: timestamp or block-derived time
- `confidence_bps`: 0..10000
- `policy_hash`: source / normalizer / prompt policy commitment
- `evidence_root`: Merkle root or digest over evidence bundle
- `source_proofs_root`: root over authenticated source proofs

---

## 5. Binary Result

Used for Polymarket-style YES/NO markets.

```text
BinaryResultBody {
  uint8 outcome
  uint8 invalid
}
```

### Semantics

- `outcome = 1` means YES
- `outcome = 0` means NO
- `invalid = 1` means the market is invalid regardless of YES/NO field

### Canonical JSON form

```json
{
  "result_type": "BINARY",
  "outcome": 1,
  "invalid": 0
}
```

### Recommended equality rule

Binary results are equal iff both `outcome` and `invalid` are equal.

---

## 6. Enum Result

Used for winner-takes-all markets with finite choices.

```text
EnumResultBody {
  uint32 enum_index
  uint8  invalid
}
```

### Semantics

- `enum_index` is the winning option index
- `invalid = 1` means invalid market

### Canonical JSON form

```json
{
  "result_type": "ENUM",
  "enum_index": 2,
  "invalid": 0
}
```

---

## 7. Scalar Result

Used for Kalshi-style reference-value markets.

```text
ScalarResultBody {
  int128 value_int
  uint8  decimals
}
```

### Semantics

`value_int / 10^decimals` is the scalar result.

### Canonical JSON form

```json
{
  "result_type": "SCALAR",
  "value_int": 312,
  "decimals": 1
}
```

This represents `31.2`.

### Equality rule

Scalar results are equal iff both `value_int` and `decimals` match exactly.

---

## 8. Range Result

Used for bucketized scalar markets.

```text
RangeResultBody {
  uint32 bucket_index
  int128 raw_value_int
  uint8  decimals
}
```

### Semantics

- `bucket_index` is the resolved bucket
- `raw_value_int` is optional but recommended for auditability
- `decimals` scales the raw scalar

### Canonical JSON form

```json
{
  "result_type": "RANGE",
  "bucket_index": 4,
  "raw_value_int": 312,
  "decimals": 1
}
```

---

## 9. Status Result

Used for invalid or meta-resolution outputs.

```text
StatusResultBody {
  uint8 status_code
  uint32 reason_code
}
```

### Suggested reason codes

```text
REASON_NONE                  = 0
REASON_AMBIGUOUS_SPEC        = 1
REASON_SOURCE_CONFLICT       = 2
REASON_DATA_UNAVAILABLE      = 3
REASON_LATE_PUBLICATION      = 4
REASON_POLICY_VIOLATION      = 5
REASON_PROOF_FAILURE         = 6
```

### Canonical JSON form

```json
{
  "result_type": "STATUS",
  "status_code": 2,
  "reason_code": 1
}
```

---

## 10. Proof Mode Values

```text
PROOF_NONE            = 0
PROOF_EVIDENCE_DIGEST = 1
PROOF_EVIDENCE_AUTH   = 2
PROOF_TEE_ATTESTED    = 3
PROOF_ZK_AGGREGATED   = 4
PROOF_ZKML_CLASSIFIED = 5
```

---

## 11. Canonical Hashing

OracleHub should compute a canonical result hash over:

```text
canonical_result_hash =
  H(
    header ||
    type_specific_body
  )
```

For commit/reveal, commitment should be:

```text
commitment_hash =
  H(
    canonical_result_hash ||
    evidence_root ||
    proof_mode ||
    aux_hash ||
    salt
  )
```

---

## 12. Suggested ABI Envelope

A generic envelope can be used for transport and storage.

```text
OracleResultEnvelope {
  OracleResultHeader header
  bytes body
}
```

`body` must decode according to `header.result_type`.

---

## 13. Recommended `.abi` Draft

Below is a draft GTOS `.abi`-style interface for consumers of OracleHub results.

```text
interface OracleResultABI {
  struct OracleResultHeader {
    uint8   version;
    bytes32 queryId;
    bytes32 marketId;
    uint8   resultType;
    uint8   status;
    uint8   proofMode;
    uint64  finalizedAt;
    uint16  confidenceBps;
    bytes32 policyHash;
    bytes32 evidenceRoot;
    bytes32 sourceProofsRoot;
  }

  struct BinaryResultBody {
    uint8 outcome;
    uint8 invalid;
  }

  struct EnumResultBody {
    uint32 enumIndex;
    uint8  invalid;
  }

  struct ScalarResultBody {
    int128 valueInt;
    uint8  decimals;
  }

  struct RangeResultBody {
    uint32 bucketIndex;
    int128 rawValueInt;
    uint8  decimals;
  }

  struct StatusResultBody {
    uint8  statusCode;
    uint32 reasonCode;
  }

  fn hashHeader(header: OracleResultHeader) -> bytes32;
  fn hashBinaryResult(header: OracleResultHeader, body: BinaryResultBody) -> bytes32;
  fn hashEnumResult(header: OracleResultHeader, body: EnumResultBody) -> bytes32;
  fn hashScalarResult(header: OracleResultHeader, body: ScalarResultBody) -> bytes32;
  fn hashRangeResult(header: OracleResultHeader, body: RangeResultBody) -> bytes32;
  fn hashStatusResult(header: OracleResultHeader, body: StatusResultBody) -> bytes32;

  fn decodeBinary(body: bytes) -> BinaryResultBody;
  fn decodeEnum(body: bytes) -> EnumResultBody;
  fn decodeScalar(body: bytes) -> ScalarResultBody;
  fn decodeRange(body: bytes) -> RangeResultBody;
  fn decodeStatus(body: bytes) -> StatusResultBody;
}
```

---

## 14. Application Settlement Mappings

## 14.1 Polymarket-style binary market settlement

Recommended body:

```json
{
  "result_type": "BINARY",
  "outcome": 1,
  "invalid": 0
}
```

### Settlement interpretation

- if `invalid == 1`: market resolves as invalid
- else if `outcome == 1`: YES wins
- else: NO wins

## 14.2 Polymarket-style categorical market settlement

Recommended body:

```json
{
  "result_type": "ENUM",
  "enum_index": 2,
  "invalid": 0
}
```

### Settlement interpretation

- if invalid: invalid market
- else: option `enum_index` wins

## 14.3 Kalshi-style scalar market settlement

Recommended body:

```json
{
  "result_type": "SCALAR",
  "value_int": 321,
  "decimals": 1
}
```

### Settlement interpretation

The consumer computes `32.1` and evaluates market-specific range logic.

## 14.4 Kalshi-style range market settlement

Recommended body:

```json
{
  "result_type": "RANGE",
  "bucket_index": 3,
  "raw_value_int": 321,
  "decimals": 1
}
```

### Settlement interpretation

- `bucket_index` is the final bucket
- `raw_value_int` is optional supporting data

---

## 15. Challenge and Equality Considerations

To keep results slashable and comparable:

- text labels must not be part of equality rules
- option names should be external metadata
- equality is determined by structured typed fields only
- source URLs and evidence archives belong in evidence trees, not settlement bodies

---

## 16. ABI Versioning

### Version 1
Supports:

- binary
- enum
- scalar
- range
- status
- evidence-root and proof-mode binding

### Future version candidates

- explicit revision numbers for official-stat markets
- dataset root result type
- embedded publication timestamp per scalar body
- verifier key binding extensions

---

## 17. Examples

## 17.1 Example A — event market

```json
{
  "header": {
    "version": 1,
    "query_id": "0x1111",
    "market_id": "0xaaaa",
    "result_type": 1,
    "status": 1,
    "proof_mode": 2,
    "finalized_at": 1772409600,
    "confidence_bps": 9800,
    "policy_hash": "0x2222",
    "evidence_root": "0x3333",
    "source_proofs_root": "0x4444"
  },
  "body": {
    "outcome": 1,
    "invalid": 0
  }
}
```

## 17.2 Example B — scalar market

```json
{
  "header": {
    "version": 1,
    "query_id": "0x5555",
    "market_id": "0xbbbb",
    "result_type": 3,
    "status": 1,
    "proof_mode": 2,
    "finalized_at": 1772409600,
    "confidence_bps": 9950,
    "policy_hash": "0x6666",
    "evidence_root": "0x7777",
    "source_proofs_root": "0x8888"
  },
  "body": {
    "value_int": 312,
    "decimals": 1
  }
}
```

---

## 18. Conclusion

The GTOS AI Oracle Result ABI should give OracleHub and prediction markets a single canonical language for settlement.

It should be:

- small
- deterministic
- typed
- hash-friendly
- evidence-aware
- proof-compatible

For prediction markets, the most important result classes are:

- **BINARY** for event markets
- **ENUM** for categorical winner markets
- **SCALAR** for official reference values
- **RANGE** for bucketed scalar markets
- **STATUS** for invalid, disputed, and unresolvable outcomes
