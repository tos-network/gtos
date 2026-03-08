# TOS x402 Demo

This package now includes:

- `x402.go`: header parsing, exact-payment verification, raw transaction submission helpers
- `http.go`: middleware for protecting a paid HTTP endpoint
- `cmd/x402demo`: a minimal runnable paid endpoint for local integration with `autos`

## Run the demo

Start a TOS node with HTTP RPC enabled, then run:

```bash
go run ./cmd/x402demo \
  --rpc http://127.0.0.1:8545 \
  --chain-id 1337 \
  --pay-to 0x1111111111111111111111111111111111111111111111111111111111111111 \
  --amount 12345 \
  --listen :8081
```

The demo exposes:

- `GET /healthz`
- `GET /paid`

`/paid` returns `402 Payment-Required` until the caller attaches a valid TOS x402 payment envelope.

## Call it from autos

From the `autos` repository root, with a funded local wallet and `TOS_RPC_URL` set:

```bash
TOS_RPC_URL=http://127.0.0.1:8545 \
npm exec tsx --eval '
  const { getWallet } = await import("./src/identity/wallet.ts");
  const { x402Fetch } = await import("./src/conway/x402.ts");
  const { account } = await getWallet();
  const result = await x402Fetch("http://127.0.0.1:8081/paid", account);
  console.log(JSON.stringify(result, null, 2));
'
```

On success, the demo responds with JSON containing:

- `message`
- `from`
- `to`
- `amount`
- `txHash`
- `network`

## Notes

- The caller wallet must hold enough TOS to cover the payment amount.
- `--pay-to` is the recipient address for the service, not the caller address.
- The demo uses `x402.RequireExactPayment(...)` and broadcasts the verified raw transaction through TOS RPC.
