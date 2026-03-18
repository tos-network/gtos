package tosapi

import (
	"github.com/tos-network/gtos/auditreceipt"
	"github.com/tos-network/gtos/gateway"
	"github.com/tos-network/gtos/policywallet"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/settlement"
	"github.com/tos-network/gtos/tns"
)

// Register2046APIs returns the RPC API descriptors for the 2046 architecture
// modules (policy wallet, gateway, audit receipt, settlement).
//
// stateReader must return the state at the current head block.  The concrete
// return value must implement GetState/SetState — typically *state.StateDB.
func Register2046APIs(stateReader func() policywallet.StateDB) []rpc.API {
	return []rpc.API{
		{
			Namespace: "policyWallet",
			Service:   policywallet.NewPublicPolicyWalletAPI(stateReader),
		},
		{
			Namespace: "gateway",
			Service: gateway.NewPublicGatewayAPI(func() gateway.StateDB {
				return stateReader()
			}),
		},
		{
			Namespace: "auditReceipt",
			Service: auditreceipt.NewPublicAuditReceiptAPI(func() auditreceipt.StateDB {
				return stateReader()
			}),
		},
		{
			Namespace: "settlement",
			Service: settlement.NewPublicSettlementAPI(func() settlement.StateDB {
				return stateReader()
			}),
		},
		{
			Namespace: "tns",
			Service: tns.NewPublicTNSAPI(func() tns.StateDB {
				return stateReader()
			}),
		},
	}
}
