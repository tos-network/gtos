package x402

import (
	"context"
	"fmt"
	"net/http"
)

type verifiedPaymentContextKey struct{}

func ContextWithVerifiedPayment(ctx context.Context, payment *VerifiedPayment) context.Context {
	return context.WithValue(ctx, verifiedPaymentContextKey{}, payment)
}

func VerifiedPaymentFromContext(ctx context.Context) (*VerifiedPayment, bool) {
	payment, ok := ctx.Value(verifiedPaymentContextKey{}).(*VerifiedPayment)
	return payment, ok && payment != nil
}

func RequireExactPayment(requirement PaymentRequirement, broadcaster RawTransactionBroadcaster, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelope, err := ReadPaymentEnvelope(r)
		if err != nil {
			_ = WritePaymentRequired(w, requirement)
			return
		}

		verified, err := VerifyExactPayment(requirement, envelope)
		if err != nil {
			_ = WritePaymentRequired(w, requirement)
			return
		}

		if _, err := SubmitVerifiedPayment(r.Context(), broadcaster, verified); err != nil {
			http.Error(w, fmt.Sprintf("x402: submit verified payment: %v", err), http.StatusBadGateway)
			return
		}

		next.ServeHTTP(w, r.WithContext(ContextWithVerifiedPayment(r.Context(), verified)))
	})
}
