package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/tosclient"
	"github.com/tos-network/gtos/x402"
)

type rpcBroadcaster struct {
	client *tosclient.Client
}

func (b *rpcBroadcaster) SendRawTransaction(ctx context.Context, rawTx hexutil.Bytes) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTx); err != nil {
		return common.Hash{}, fmt.Errorf("decode raw transaction: %w", err)
	}
	if err := b.client.SendTransaction(ctx, tx); err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

func main() {
	var (
		listenAddr = flag.String("listen", ":8081", "HTTP listen address")
		rpcURL     = flag.String("rpc", "http://127.0.0.1:8545", "TOS HTTP RPC URL")
		path       = flag.String("path", "/paid", "paid endpoint path")
		chainIDArg = flag.String("chain-id", "1337", "TOS chain ID")
		payToArg   = flag.String("pay-to", "", "service recipient TOS address")
		amountArg  = flag.String("amount", "12345", "required payment amount in base units")
		message    = flag.String("message", "paid endpoint unlocked", "response message")
	)
	flag.Parse()

	if *payToArg == "" {
		log.Fatal("--pay-to is required")
	}
	chainID, ok := new(big.Int).SetString(*chainIDArg, 10)
	if !ok || chainID.Sign() <= 0 {
		log.Fatalf("invalid --chain-id %q", *chainIDArg)
	}
	amount, ok := new(big.Int).SetString(*amountArg, 10)
	if !ok || amount.Sign() <= 0 {
		log.Fatalf("invalid --amount %q", *amountArg)
	}

	client, err := tosclient.Dial(*rpcURL)
	if err != nil {
		log.Fatalf("dial TOS RPC: %v", err)
	}
	defer client.Close()

	recipient := common.HexToAddress(*payToArg)
	requirement := x402.NewExactNativeRequirement(chainID, recipient, amount, "minimal TOS x402 demo")
	broadcaster := &rpcBroadcaster{client: client}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"network": requirement.Network,
			"path":    *path,
		})
	})
	mux.Handle(*path, x402.RequireExactPayment(requirement, broadcaster, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified, ok := x402.VerifiedPaymentFromContext(r.Context())
		if !ok {
			http.Error(w, "missing verified payment in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"message":      *message,
			"network":      requirement.Network,
			"from":         verified.From.Hex(),
			"to":           verified.To.Hex(),
			"amount":       verified.Value.String(),
			"txHash":       verified.TransactionHash.Hex(),
			"receivedAt":   time.Now().UTC().Format(time.RFC3339),
			"paidEndpoint": *path,
		})
	})))

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("x402 demo listening on %s", *listenAddr)
	log.Printf("health endpoint: http://127.0.0.1%s/healthz", *listenAddr)
	log.Printf("paid endpoint:   http://127.0.0.1%s%s", *listenAddr, *path)
	log.Printf("network:         %s", requirement.Network)
	log.Printf("recipient:       %s", recipient.Hex())
	log.Printf("amount:          %s", amount.String())

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
