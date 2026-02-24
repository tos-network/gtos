package flags

import "github.com/urfave/cli/v2"

const (
	TOSCategory        = "TOS"
	LightCategory      = "LIGHT CLIENT"
	DevCategory        = "DEVELOPER CHAIN"
	DPoSCategory       = "DPOS"
	TxPoolCategory     = "TRANSACTION POOL"
	PerfCategory       = "PERFORMANCE TUNING"
	AccountCategory    = "ACCOUNT"
	APICategory        = "API AND CONSOLE"
	NetworkingCategory = "NETWORKING"
	MinerCategory      = "MINER"
	TxPriceCategory    = "TX PRICE ORACLE"
	VMCategory         = "VIRTUAL MACHINE"
	LoggingCategory    = "LOGGING AND DEBUGGING"
	MetricsCategory    = "METRICS AND STATS"
	MiscCategory       = "MISC"
	DeprecatedCategory = "ALIASED (deprecated)"
)

func init() {
	cli.HelpFlag.(*cli.BoolFlag).Category = MiscCategory
	cli.VersionFlag.(*cli.BoolFlag).Category = MiscCategory
}
