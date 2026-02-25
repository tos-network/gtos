// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// Package utils contains internal helper functions for go-tos commands.
package utils

import (
	"crypto/ecdsa"
	"fmt"
	"math"
	"os"
	godebug "runtime/debug"
	"strconv"
	"strings"
	"time"

	gopsutil "github.com/shirou/gopsutil/mem"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/fdlimit"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/internal/flags"
	"github.com/tos-network/gtos/internal/tosapi"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/metrics"
	"github.com/tos-network/gtos/metrics/exp"
	"github.com/tos-network/gtos/metrics/influxdb"
	"github.com/tos-network/gtos/miner"
	"github.com/tos-network/gtos/node"
	"github.com/tos-network/gtos/p2p"
	"github.com/tos-network/gtos/p2p/enode"
	"github.com/tos-network/gtos/p2p/nat"
	"github.com/tos-network/gtos/p2p/netutil"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tos"
	"github.com/tos-network/gtos/tos/downloader"
	"github.com/tos-network/gtos/tos/filters"
	"github.com/tos-network/gtos/tos/tosconfig"
	"github.com/tos-network/gtos/tosdb"
	"github.com/tos-network/gtos/tosdb/remotedb"
	"github.com/urfave/cli/v2"
)

// These are all the command line flags we support.
// If you add to this list, please remember to include the
// flag in the appropriate command definition.
//
// The flags are defined here so their names and help texts
// are the same for all commands.

var (
	// General settings
	DataDirFlag = &flags.DirectoryFlag{
		Name:     "datadir",
		Usage:    "Data directory for the databases and keystore",
		Value:    flags.DirectoryString(node.DefaultDataDir()),
		Category: flags.TOSCategory,
	}
	RemoteDBFlag = &cli.StringFlag{
		Name:     "remotedb",
		Usage:    "URL for remote database",
		Category: flags.LoggingCategory,
	}
	AncientFlag = &flags.DirectoryFlag{
		Name:     "datadir.ancient",
		Usage:    "Root directory for ancient data (default = inside chaindata)",
		Category: flags.TOSCategory,
	}
	MinFreeDiskSpaceFlag = &flags.DirectoryFlag{
		Name:     "datadir.minfreedisk",
		Usage:    "Minimum free disk space in MB, once reached triggers auto shut down (default = --cache.gc converted to MB, 0 = disabled)",
		Category: flags.TOSCategory,
	}
	KeyStoreDirFlag = &flags.DirectoryFlag{
		Name:     "keystore",
		Usage:    "Directory for the keystore (default = inside the datadir)",
		Category: flags.AccountCategory,
	}
	NetworkIdFlag = &cli.Uint64Flag{
		Name:     "networkid",
		Usage:    "Explicitly set network id (integer)",
		Value:    tosconfig.Defaults.NetworkId,
		Category: flags.TOSCategory,
	}
	MainnetFlag = &cli.BoolFlag{
		Name:     "mainnet",
		Usage:    "TOS mainnet",
		Category: flags.TOSCategory,
	}

	// Dev mode
	DeveloperFlag = &cli.BoolFlag{
		Name:     "dev",
		Usage:    "Ephemeral proof-of-authority network with a pre-funded developer account, mining enabled",
		Category: flags.DevCategory,
	}
	DeveloperPeriodFlag = &cli.IntFlag{
		Name:     "dev.period",
		Usage:    "Block period in seconds for developer mode (legacy; overridden by --dev.periodms when set)",
		Value:    1,
		Category: flags.DevCategory,
	}
	DeveloperPeriodMsFlag = &cli.Uint64Flag{
		Name:     "dev.periodms",
		Usage:    "Block period in milliseconds for developer mode (overrides --dev.period when set)",
		Value:    params.DPoSBlockPeriodMs,
		Category: flags.DevCategory,
	}
	DeveloperGasLimitFlag = &cli.Uint64Flag{
		Name:     "dev.gaslimit",
		Usage:    "Initial block gas limit",
		Value:    30000000,
		Category: flags.DevCategory,
	}

	IdentityFlag = &cli.StringFlag{
		Name:     "identity",
		Usage:    "Custom node name",
		Category: flags.NetworkingCategory,
	}
	DocRootFlag = &flags.DirectoryFlag{
		Name:     "docroot",
		Usage:    "Document Root for HTTPClient file scheme",
		Value:    flags.DirectoryString(flags.HomeDir()),
		Category: flags.APICategory,
	}
	ExitWhenSyncedFlag = &cli.BoolFlag{
		Name:     "exitwhensynced",
		Usage:    "Exits after block synchronisation completes",
		Category: flags.TOSCategory,
	}

	// Dump command options.
	IterativeOutputFlag = &cli.BoolFlag{
		Name:  "iterative",
		Usage: "Print streaming JSON iteratively, delimited by newlines",
		Value: true,
	}
	ExcludeStorageFlag = &cli.BoolFlag{
		Name:  "nostorage",
		Usage: "Exclude storage entries (save db lookups)",
	}
	IncludeIncompletesFlag = &cli.BoolFlag{
		Name:  "incompletes",
		Usage: "Include accounts for which we don't have the address (missing preimage)",
	}
	ExcludeCodeFlag = &cli.BoolFlag{
		Name:  "nocode",
		Usage: "Exclude contract code (save db lookups)",
	}
	StartKeyFlag = &cli.StringFlag{
		Name:  "start",
		Usage: "Start position. Either a hash or address",
		Value: "0x0000000000000000000000000000000000000000000000000000000000000000",
	}
	DumpLimitFlag = &cli.Uint64Flag{
		Name:  "limit",
		Usage: "Max number of elements (0 = no limit)",
		Value: 0,
	}

	defaultSyncMode = tosconfig.Defaults.SyncMode
	SyncModeFlag    = &flags.TextMarshalerFlag{
		Name:     "syncmode",
		Usage:    `Blockchain sync mode ("snap", "full" or "light")`,
		Value:    &defaultSyncMode,
		Category: flags.TOSCategory,
	}
	GCModeFlag = &cli.StringFlag{
		Name:     "gcmode",
		Usage:    `Blockchain garbage collection mode ("full", "archive")`,
		Value:    "full",
		Category: flags.TOSCategory,
	}
	SnapshotFlag = &cli.BoolFlag{
		Name:     "snapshot",
		Usage:    `Enables snapshot-database mode (default = enable)`,
		Value:    true,
		Category: flags.TOSCategory,
	}
	TxLookupLimitFlag = &cli.Uint64Flag{
		Name:     "txlookuplimit",
		Usage:    "Number of recent blocks to maintain transactions index for (default = about one year, 0 = entire chain)",
		Value:    tosconfig.Defaults.TxLookupLimit,
		Category: flags.TOSCategory,
	}
	LightKDFFlag = &cli.BoolFlag{
		Name:     "lightkdf",
		Usage:    "Reduce key-derivation RAM & CPU usage at some expense of KDF strength",
		Category: flags.AccountCategory,
	}
	TOSRequiredBlocksFlag = &cli.StringFlag{
		Name:     "tos.requiredblocks",
		Usage:    "Comma separated block number-to-hash mappings to require for peering (<number>=<hash>)",
		Category: flags.TOSCategory,
	}
	LegacyWhitelistFlag = &cli.StringFlag{
		Name:     "whitelist",
		Usage:    "Comma separated block number-to-hash mappings to enforce (<number>=<hash>) (deprecated in favor of --tos.requiredblocks)",
		Category: flags.DeprecatedCategory,
	}
	BloomFilterSizeFlag = &cli.Uint64Flag{
		Name:     "bloomfilter.size",
		Usage:    "Megabytes of memory allocated to bloom-filter for pruning",
		Value:    2048,
		Category: flags.TOSCategory,
	}
	OverrideTerminalTotalDifficulty = &flags.BigFlag{
		Name:     "override.terminaltotaldifficulty",
		Usage:    "Manually specify TerminalTotalDifficulty, overriding the bundled setting",
		Category: flags.TOSCategory,
	}
	OverrideTerminalTotalDifficultyPassed = &cli.BoolFlag{
		Name:     "override.terminaltotaldifficultypassed",
		Usage:    "Manually specify TerminalTotalDifficultyPassed, overriding the bundled setting",
		Category: flags.TOSCategory,
	}
	// Light server and client settings
	LightServeFlag = &cli.IntFlag{
		Name:     "light.serve",
		Usage:    "Maximum percentage of time allowed for serving LES requests (multi-threaded processing allows values over 100)",
		Value:    tosconfig.Defaults.LightServ,
		Category: flags.LightCategory,
	}
	LightIngressFlag = &cli.IntFlag{
		Name:     "light.ingress",
		Usage:    "Incoming bandwidth limit for serving light clients (kilobytes/sec, 0 = unlimited)",
		Value:    tosconfig.Defaults.LightIngress,
		Category: flags.LightCategory,
	}
	LightEgressFlag = &cli.IntFlag{
		Name:     "light.egress",
		Usage:    "Outgoing bandwidth limit for serving light clients (kilobytes/sec, 0 = unlimited)",
		Value:    tosconfig.Defaults.LightEgress,
		Category: flags.LightCategory,
	}
	LightMaxPeersFlag = &cli.IntFlag{
		Name:     "light.maxpeers",
		Usage:    "Maximum number of light clients to serve, or light servers to attach to",
		Value:    tosconfig.Defaults.LightPeers,
		Category: flags.LightCategory,
	}
	UltraLightServersFlag = &cli.StringFlag{
		Name:     "ulc.servers",
		Usage:    "List of trusted ultra-light servers",
		Value:    strings.Join(tosconfig.Defaults.UltraLightServers, ","),
		Category: flags.LightCategory,
	}
	UltraLightFractionFlag = &cli.IntFlag{
		Name:     "ulc.fraction",
		Usage:    "Minimum % of trusted ultra-light servers required to announce a new head",
		Value:    tosconfig.Defaults.UltraLightFraction,
		Category: flags.LightCategory,
	}
	UltraLightOnlyAnnounceFlag = &cli.BoolFlag{
		Name:     "ulc.onlyannounce",
		Usage:    "Ultra light server sends announcements only",
		Category: flags.LightCategory,
	}
	LightNoPruneFlag = &cli.BoolFlag{
		Name:     "light.nopruning",
		Usage:    "Disable ancient light chain data pruning",
		Category: flags.LightCategory,
	}
	LightNoSyncServeFlag = &cli.BoolFlag{
		Name:     "light.nosyncserve",
		Usage:    "Enables serving light clients before syncing",
		Category: flags.LightCategory,
	}

	// Transaction pool settings
	TxPoolLocalsFlag = &cli.StringFlag{
		Name:     "txpool.locals",
		Usage:    "Comma separated accounts to treat as locals (no flush, priority inclusion)",
		Category: flags.TxPoolCategory,
	}
	TxPoolNoLocalsFlag = &cli.BoolFlag{
		Name:     "txpool.nolocals",
		Usage:    "Disables price exemptions for locally submitted transactions",
		Category: flags.TxPoolCategory,
	}
	TxPoolJournalFlag = &cli.StringFlag{
		Name:     "txpool.journal",
		Usage:    "Disk journal for local transaction to survive node restarts",
		Value:    core.DefaultTxPoolConfig.Journal,
		Category: flags.TxPoolCategory,
	}
	TxPoolRejournalFlag = &cli.DurationFlag{
		Name:     "txpool.rejournal",
		Usage:    "Time interval to regenerate the local transaction journal",
		Value:    core.DefaultTxPoolConfig.Rejournal,
		Category: flags.TxPoolCategory,
	}
	TxPoolPriceLimitFlag = &cli.Uint64Flag{
		Name:     "txpool.pricelimit",
		Usage:    "Minimum tx price limit to enforce for acceptance into the pool",
		Value:    tosconfig.Defaults.TxPool.PriceLimit,
		Category: flags.TxPoolCategory,
	}
	TxPoolPriceBumpFlag = &cli.Uint64Flag{
		Name:     "txpool.pricebump",
		Usage:    "Price bump percentage to replace an already existing transaction",
		Value:    tosconfig.Defaults.TxPool.PriceBump,
		Category: flags.TxPoolCategory,
	}
	TxPoolAccountSlotsFlag = &cli.Uint64Flag{
		Name:     "txpool.accountslots",
		Usage:    "Minimum number of executable transaction slots guaranteed per account",
		Value:    tosconfig.Defaults.TxPool.AccountSlots,
		Category: flags.TxPoolCategory,
	}
	TxPoolGlobalSlotsFlag = &cli.Uint64Flag{
		Name:     "txpool.globalslots",
		Usage:    "Maximum number of executable transaction slots for all accounts",
		Value:    tosconfig.Defaults.TxPool.GlobalSlots,
		Category: flags.TxPoolCategory,
	}
	TxPoolAccountQueueFlag = &cli.Uint64Flag{
		Name:     "txpool.accountqueue",
		Usage:    "Maximum number of non-executable transaction slots permitted per account",
		Value:    tosconfig.Defaults.TxPool.AccountQueue,
		Category: flags.TxPoolCategory,
	}
	TxPoolGlobalQueueFlag = &cli.Uint64Flag{
		Name:     "txpool.globalqueue",
		Usage:    "Maximum number of non-executable transaction slots for all accounts",
		Value:    tosconfig.Defaults.TxPool.GlobalQueue,
		Category: flags.TxPoolCategory,
	}
	TxPoolLifetimeFlag = &cli.DurationFlag{
		Name:     "txpool.lifetime",
		Usage:    "Maximum amount of time non-executable transaction are queued",
		Value:    tosconfig.Defaults.TxPool.Lifetime,
		Category: flags.TxPoolCategory,
	}

	// Performance tuning settings
	CacheFlag = &cli.IntFlag{
		Name:     "cache",
		Usage:    "Megabytes of memory allocated to internal caching (default = 4096 mainnet full node, 128 light mode)",
		Value:    1024,
		Category: flags.PerfCategory,
	}
	CacheDatabaseFlag = &cli.IntFlag{
		Name:     "cache.database",
		Usage:    "Percentage of cache memory allowance to use for database io",
		Value:    50,
		Category: flags.PerfCategory,
	}
	CacheTrieFlag = &cli.IntFlag{
		Name:     "cache.trie",
		Usage:    "Percentage of cache memory allowance to use for trie caching (default = 15% full mode, 30% archive mode)",
		Value:    15,
		Category: flags.PerfCategory,
	}
	CacheTrieJournalFlag = &cli.StringFlag{
		Name:     "cache.trie.journal",
		Usage:    "Disk journal directory for trie cache to survive node restarts",
		Value:    tosconfig.Defaults.TrieCleanCacheJournal,
		Category: flags.PerfCategory,
	}
	CacheTrieRejournalFlag = &cli.DurationFlag{
		Name:     "cache.trie.rejournal",
		Usage:    "Time interval to regenerate the trie cache journal",
		Value:    tosconfig.Defaults.TrieCleanCacheRejournal,
		Category: flags.PerfCategory,
	}
	CacheGCFlag = &cli.IntFlag{
		Name:     "cache.gc",
		Usage:    "Percentage of cache memory allowance to use for trie pruning (default = 25% full mode, 0% archive mode)",
		Value:    25,
		Category: flags.PerfCategory,
	}
	CacheSnapshotFlag = &cli.IntFlag{
		Name:     "cache.snapshot",
		Usage:    "Percentage of cache memory allowance to use for snapshot caching (default = 10% full mode, 20% archive mode)",
		Value:    10,
		Category: flags.PerfCategory,
	}
	CacheNoPrefetchFlag = &cli.BoolFlag{
		Name:     "cache.noprefetch",
		Usage:    "Disable heuristic state prefetch during block import (less CPU and disk IO, more time waiting for data)",
		Category: flags.PerfCategory,
	}
	CachePreimagesFlag = &cli.BoolFlag{
		Name:     "cache.preimages",
		Usage:    "Enable recording the SHA3/keccak preimages of trie keys",
		Category: flags.PerfCategory,
	}
	CacheLogSizeFlag = &cli.IntFlag{
		Name:     "cache.blocklogs",
		Usage:    "Size (in number of blocks) of the log cache for filtering",
		Category: flags.PerfCategory,
		Value:    tosconfig.Defaults.FilterLogCacheSize,
	}
	FDLimitFlag = &cli.IntFlag{
		Name:     "fdlimit",
		Usage:    "Raise the open file descriptor resource limit (default = system fd limit)",
		Category: flags.PerfCategory,
	}

	// Miner settings
	MiningEnabledFlag = &cli.BoolFlag{
		Name:     "mine",
		Usage:    "Enable mining",
		Category: flags.MinerCategory,
	}
	MinerThreadsFlag = &cli.IntFlag{
		Name:     "miner.threads",
		Usage:    "Number of CPU threads to use for mining",
		Value:    0,
		Category: flags.MinerCategory,
	}
	MinerNotifyFlag = &cli.StringFlag{
		Name:     "miner.notify",
		Usage:    "Comma separated HTTP URL list to notify of new work packages",
		Category: flags.MinerCategory,
	}
	MinerNotifyFullFlag = &cli.BoolFlag{
		Name:     "miner.notify.full",
		Usage:    "Notify with pending block headers instead of work packages",
		Category: flags.MinerCategory,
	}
	MinerGasLimitFlag = &cli.Uint64Flag{
		Name:     "miner.gaslimit",
		Usage:    "Target gas ceiling for mined blocks",
		Value:    tosconfig.Defaults.Miner.GasCeil,
		Category: flags.MinerCategory,
	}
	MinerCoinbaseFlag = &cli.StringFlag{
		Name:     "miner.coinbase",
		Aliases:  []string{"miner.etherbase"},
		Usage:    "Public address for block mining rewards (default = first account)",
		Value:    "0",
		Category: flags.MinerCategory,
	}
	MinerTosbaseFlag   = MinerCoinbaseFlag // Deprecated alias.
	MinerExtraDataFlag = &cli.StringFlag{
		Name:     "miner.extradata",
		Usage:    "Block extra data set by the miner (default = client version)",
		Category: flags.MinerCategory,
	}
	MinerRecommitIntervalFlag = &cli.DurationFlag{
		Name:     "miner.recommit",
		Usage:    "Time interval to recreate the block being mined",
		Value:    tosconfig.Defaults.Miner.Recommit,
		Category: flags.MinerCategory,
	}
	MinerNoVerifyFlag = &cli.BoolFlag{
		Name:     "miner.noverify",
		Usage:    "Disable remote sealing verification",
		Category: flags.MinerCategory,
	}

	// Account settings
	UnlockedAccountFlag = &cli.StringFlag{
		Name:     "unlock",
		Usage:    "Comma separated list of accounts to unlock",
		Value:    "",
		Category: flags.AccountCategory,
	}
	PasswordFileFlag = &cli.PathFlag{
		Name:      "password",
		Usage:     "Password file to use for non-interactive password input",
		TakesFile: true,
		Category:  flags.AccountCategory,
	}
	InsecureUnlockAllowedFlag = &cli.BoolFlag{
		Name:     "allow-insecure-unlock",
		Usage:    "Allow insecure account unlocking when account-related RPCs are exposed by http",
		Category: flags.AccountCategory,
	}

	// TVM settings
	VMEnableDebugFlag = &cli.BoolFlag{
		Name:     "vmdebug",
		Usage:    "Record information useful for VM and contract debugging",
		Category: flags.VMCategory,
	}

	// API options.
	RPCGlobalGasCapFlag = &cli.Uint64Flag{
		Name:     "rpc.gascap",
		Usage:    "Sets a cap on gas that can be used in eth_call/estimateGas (0=infinite)",
		Value:    tosconfig.Defaults.RPCGasCap,
		Category: flags.APICategory,
	}
	RPCGlobalEVMTimeoutFlag = &cli.DurationFlag{
		Name:     "rpc.evmtimeout",
		Usage:    "Sets a timeout used for eth_call (0=infinite)",
		Value:    tosconfig.Defaults.RPCEVMTimeout,
		Category: flags.APICategory,
	}
	RPCGlobalTxFeeCapFlag = &cli.Float64Flag{
		Name:     "rpc.txfeecap",
		Usage:    "Sets a cap on transaction fee (in tos) that can be sent via the RPC APIs (0 = no cap)",
		Value:    tosconfig.Defaults.RPCTxFeeCap,
		Category: flags.APICategory,
	}
	// Authenticated RPC HTTP settings
	AuthListenFlag = &cli.StringFlag{
		Name:     "authrpc.addr",
		Usage:    "Listening address for authenticated APIs",
		Value:    node.DefaultConfig.AuthAddr,
		Category: flags.APICategory,
	}
	AuthPortFlag = &cli.IntFlag{
		Name:     "authrpc.port",
		Usage:    "Listening port for authenticated APIs",
		Value:    node.DefaultConfig.AuthPort,
		Category: flags.APICategory,
	}
	AuthVirtualHostsFlag = &cli.StringFlag{
		Name:     "authrpc.vhosts",
		Usage:    "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value:    strings.Join(node.DefaultConfig.AuthVirtualHosts, ","),
		Category: flags.APICategory,
	}
	JWTSecretFlag = &cli.StringFlag{
		Name:     "authrpc.jwtsecret",
		Usage:    "Path to a JWT secret to use for authenticated RPC endpoints",
		Category: flags.APICategory,
	}

	// Logging and debug settings
	TOSStatsURLFlag = &cli.StringFlag{
		Name:     "tosstats",
		Usage:    "Reporting URL of a tosstats service (nodename:secret@host:port)",
		Category: flags.MetricsCategory,
	}
	FakePoWFlag = &cli.BoolFlag{
		Name:     "fakepow",
		Usage:    "Disables proof-of-work verification",
		Category: flags.LoggingCategory,
	}
	NoCompactionFlag = &cli.BoolFlag{
		Name:     "nocompaction",
		Usage:    "Disables db compaction after import",
		Category: flags.LoggingCategory,
	}

	IgnoreLegacyReceiptsFlag = &cli.BoolFlag{
		Name:     "ignore-legacy-receipts",
		Usage:    "GTOS will start up even if there are legacy receipts in freezer",
		Category: flags.MiscCategory,
	}

	// RPC settings
	IPCDisabledFlag = &cli.BoolFlag{
		Name:     "ipcdisable",
		Usage:    "Disable the IPC-RPC server",
		Category: flags.APICategory,
	}
	IPCPathFlag = &flags.DirectoryFlag{
		Name:     "ipcpath",
		Usage:    "Filename for IPC socket/pipe within the datadir (explicit paths escape it)",
		Category: flags.APICategory,
	}
	HTTPEnabledFlag = &cli.BoolFlag{
		Name:     "http",
		Usage:    "Enable the HTTP-RPC server",
		Category: flags.APICategory,
	}
	HTTPListenAddrFlag = &cli.StringFlag{
		Name:     "http.addr",
		Usage:    "HTTP-RPC server listening interface",
		Value:    node.DefaultHTTPHost,
		Category: flags.APICategory,
	}
	HTTPPortFlag = &cli.IntFlag{
		Name:     "http.port",
		Usage:    "HTTP-RPC server listening port",
		Value:    node.DefaultHTTPPort,
		Category: flags.APICategory,
	}
	HTTPCORSDomainFlag = &cli.StringFlag{
		Name:     "http.corsdomain",
		Usage:    "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
		Value:    "",
		Category: flags.APICategory,
	}
	HTTPVirtualHostsFlag = &cli.StringFlag{
		Name:     "http.vhosts",
		Usage:    "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value:    strings.Join(node.DefaultConfig.HTTPVirtualHosts, ","),
		Category: flags.APICategory,
	}
	HTTPApiFlag = &cli.StringFlag{
		Name:     "http.api",
		Usage:    "API's offered over the HTTP-RPC interface",
		Value:    "",
		Category: flags.APICategory,
	}
	HTTPPathPrefixFlag = &cli.StringFlag{
		Name:     "http.rpcprefix",
		Usage:    "HTTP path path prefix on which JSON-RPC is served. Use '/' to serve on all paths.",
		Value:    "",
		Category: flags.APICategory,
	}
	GraphQLEnabledFlag = &cli.BoolFlag{
		Name:     "graphql",
		Usage:    "Enable GraphQL on the HTTP-RPC server. Note that GraphQL can only be started if an HTTP server is started as well.",
		Category: flags.APICategory,
	}
	GraphQLCORSDomainFlag = &cli.StringFlag{
		Name:     "graphql.corsdomain",
		Usage:    "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
		Value:    "",
		Category: flags.APICategory,
	}
	GraphQLVirtualHostsFlag = &cli.StringFlag{
		Name:     "graphql.vhosts",
		Usage:    "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value:    strings.Join(node.DefaultConfig.GraphQLVirtualHosts, ","),
		Category: flags.APICategory,
	}
	WSEnabledFlag = &cli.BoolFlag{
		Name:     "ws",
		Usage:    "Enable the WS-RPC server",
		Category: flags.APICategory,
	}
	WSListenAddrFlag = &cli.StringFlag{
		Name:     "ws.addr",
		Usage:    "WS-RPC server listening interface",
		Value:    node.DefaultWSHost,
		Category: flags.APICategory,
	}
	WSPortFlag = &cli.IntFlag{
		Name:     "ws.port",
		Usage:    "WS-RPC server listening port",
		Value:    node.DefaultWSPort,
		Category: flags.APICategory,
	}
	WSApiFlag = &cli.StringFlag{
		Name:     "ws.api",
		Usage:    "API's offered over the WS-RPC interface",
		Value:    "",
		Category: flags.APICategory,
	}
	WSAllowedOriginsFlag = &cli.StringFlag{
		Name:     "ws.origins",
		Usage:    "Origins from which to accept websockets requests",
		Value:    "",
		Category: flags.APICategory,
	}
	WSPathPrefixFlag = &cli.StringFlag{
		Name:     "ws.rpcprefix",
		Usage:    "HTTP path prefix on which JSON-RPC is served. Use '/' to serve on all paths.",
		Value:    "",
		Category: flags.APICategory,
	}
	ExecFlag = &cli.StringFlag{
		Name:     "exec",
		Usage:    "Execute JavaScript statement",
		Category: flags.APICategory,
	}
	PreloadJSFlag = &cli.StringFlag{
		Name:     "preload",
		Usage:    "Comma separated list of JavaScript files to preload into the console",
		Category: flags.APICategory,
	}
	// Network Settings
	MaxPeersFlag = &cli.IntFlag{
		Name:     "maxpeers",
		Usage:    "Maximum number of network peers (network disabled if set to 0)",
		Value:    node.DefaultConfig.P2P.MaxPeers,
		Category: flags.NetworkingCategory,
	}
	MaxPendingPeersFlag = &cli.IntFlag{
		Name:     "maxpendpeers",
		Usage:    "Maximum number of pending connection attempts (defaults used if set to 0)",
		Value:    node.DefaultConfig.P2P.MaxPendingPeers,
		Category: flags.NetworkingCategory,
	}
	ListenPortFlag = &cli.IntFlag{
		Name:     "port",
		Usage:    "Network listening port",
		Value:    30303,
		Category: flags.NetworkingCategory,
	}
	BootnodesFlag = &cli.StringFlag{
		Name:     "bootnodes",
		Usage:    "Comma separated enode URLs for P2P discovery bootstrap",
		Value:    "",
		Category: flags.NetworkingCategory,
	}
	NodeKeyFileFlag = &cli.StringFlag{
		Name:     "nodekey",
		Usage:    "P2P node key file",
		Category: flags.NetworkingCategory,
	}
	NodeKeyHexFlag = &cli.StringFlag{
		Name:     "nodekeyhex",
		Usage:    "P2P node key as hex (for testing)",
		Category: flags.NetworkingCategory,
	}
	NATFlag = &cli.StringFlag{
		Name:     "nat",
		Usage:    "NAT port mapping mechanism (any|none|upnp|pmp|extip:<IP>)",
		Value:    "any",
		Category: flags.NetworkingCategory,
	}
	NoDiscoverFlag = &cli.BoolFlag{
		Name:     "nodiscover",
		Usage:    "Disables the peer discovery mechanism (manual peer addition)",
		Category: flags.NetworkingCategory,
	}
	DiscoveryV5Flag = &cli.BoolFlag{
		Name:     "v5disc",
		Usage:    "Enables the experimental RLPx V5 (Topic Discovery) mechanism",
		Category: flags.NetworkingCategory,
	}
	NetrestrictFlag = &cli.StringFlag{
		Name:     "netrestrict",
		Usage:    "Restricts network communication to the given IP networks (CIDR masks)",
		Category: flags.NetworkingCategory,
	}
	DNSDiscoveryFlag = &cli.StringFlag{
		Name:     "discovery.dns",
		Usage:    "Sets DNS discovery entry points (use \"\" to disable DNS)",
		Category: flags.NetworkingCategory,
	}
	DiscoveryPortFlag = &cli.IntFlag{
		Name:     "discovery.port",
		Usage:    "Use a custom UDP port for P2P discovery",
		Value:    30303,
		Category: flags.NetworkingCategory,
	}

	// Console
	JSpathFlag = &flags.DirectoryFlag{
		Name:     "jspath",
		Usage:    "JavaScript root path for `loadScript`",
		Value:    flags.DirectoryString("."),
		Category: flags.APICategory,
	}

	// Metrics flags
	MetricsEnabledFlag = &cli.BoolFlag{
		Name:     "metrics",
		Usage:    "Enable metrics collection and reporting",
		Category: flags.MetricsCategory,
	}
	MetricsEnabledExpensiveFlag = &cli.BoolFlag{
		Name:     "metrics.expensive",
		Usage:    "Enable expensive metrics collection and reporting",
		Category: flags.MetricsCategory,
	}

	// MetricsHTTPFlag defines the endpoint for a stand-alone metrics HTTP endpoint.
	// Since the pprof service enables sensitive/vulnerable behavior, this allows a user
	// to enable a public-OK metrics endpoint without having to worry about ALSO exposing
	// other profiling behavior or information.
	MetricsHTTPFlag = &cli.StringFlag{
		Name:     "metrics.addr",
		Usage:    "Enable stand-alone metrics HTTP server listening interface",
		Value:    metrics.DefaultConfig.HTTP,
		Category: flags.MetricsCategory,
	}
	MetricsPortFlag = &cli.IntFlag{
		Name:     "metrics.port",
		Usage:    "Metrics HTTP server listening port",
		Value:    metrics.DefaultConfig.Port,
		Category: flags.MetricsCategory,
	}
	MetricsEnableInfluxDBFlag = &cli.BoolFlag{
		Name:     "metrics.influxdb",
		Usage:    "Enable metrics export/push to an external InfluxDB database",
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBEndpointFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.endpoint",
		Usage:    "InfluxDB API endpoint to report metrics to",
		Value:    metrics.DefaultConfig.InfluxDBEndpoint,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBDatabaseFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.database",
		Usage:    "InfluxDB database name to push reported metrics to",
		Value:    metrics.DefaultConfig.InfluxDBDatabase,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBUsernameFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.username",
		Usage:    "Username to authorize access to the database",
		Value:    metrics.DefaultConfig.InfluxDBUsername,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBPasswordFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.password",
		Usage:    "Password to authorize access to the database",
		Value:    metrics.DefaultConfig.InfluxDBPassword,
		Category: flags.MetricsCategory,
	}
	// Tags are part of every measurement sent to InfluxDB. Queries on tags are faster in InfluxDB.
	// For example `host` tag could be used so that we can group all nodes and average a measurement
	// across all of them, but also so that we can select a specific node and inspect its measurements.
	// https://docs.influxdata.com/influxdb/v1.4/concepts/key_concepts/#tag-key
	MetricsInfluxDBTagsFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.tags",
		Usage:    "Comma-separated InfluxDB tags (key/values) attached to all measurements",
		Value:    metrics.DefaultConfig.InfluxDBTags,
		Category: flags.MetricsCategory,
	}

	MetricsEnableInfluxDBV2Flag = &cli.BoolFlag{
		Name:     "metrics.influxdbv2",
		Usage:    "Enable metrics export/push to an external InfluxDB v2 database",
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBTokenFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.token",
		Usage:    "Token to authorize access to the database (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBToken,
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBBucketFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.bucket",
		Usage:    "InfluxDB bucket name to push reported metrics to (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBBucket,
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBOrganizationFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.organization",
		Usage:    "InfluxDB organization name (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBOrganization,
		Category: flags.MetricsCategory,
	}
)

var (
	// NetworkFlags is the flag group of all built-in supported networks.
	NetworkFlags = []cli.Flag{
		MainnetFlag,
	}

	// DatabasePathFlags is the flag group of all database path flags.
	DatabasePathFlags = []cli.Flag{
		DataDirFlag,
		AncientFlag,
		RemoteDBFlag,
	}
)

// MakeDataDir retrieves the currently requested data directory, terminating
// if none (or the empty string) is specified.
func MakeDataDir(ctx *cli.Context) string {
	if path := ctx.String(DataDirFlag.Name); path != "" {
		return path
	}
	Fatalf("Cannot determine default data directory, please set manually (--datadir)")
	return ""
}

// setNodeKey creates a node key from set command line flags, either loading it
// from a file or as a specified hex value. If neither flags were provided, this
// method returns nil and an emphemeral key is to be generated.
func setNodeKey(ctx *cli.Context, cfg *p2p.Config) {
	var (
		hex  = ctx.String(NodeKeyHexFlag.Name)
		file = ctx.String(NodeKeyFileFlag.Name)
		key  *ecdsa.PrivateKey
		err  error
	)
	switch {
	case file != "" && hex != "":
		Fatalf("Options %q and %q are mutually exclusive", NodeKeyFileFlag.Name, NodeKeyHexFlag.Name)
	case file != "":
		if key, err = crypto.LoadECDSA(file); err != nil {
			Fatalf("Option %q: %v", NodeKeyFileFlag.Name, err)
		}
		cfg.PrivateKey = key
	case hex != "":
		if key, err = crypto.HexToECDSA(hex); err != nil {
			Fatalf("Option %q: %v", NodeKeyHexFlag.Name, err)
		}
		cfg.PrivateKey = key
	}
}

// setNodeUserIdent creates the user identifier from CLI flags.
func setNodeUserIdent(ctx *cli.Context, cfg *node.Config) {
	if identity := ctx.String(IdentityFlag.Name); len(identity) > 0 {
		cfg.UserIdent = identity
	}
}

// setBootstrapNodes creates a list of bootstrap nodes from the command line
// flags, reverting to pre-configured ones if none have been specified.
func setBootstrapNodes(ctx *cli.Context, cfg *p2p.Config) {
	urls := params.MainnetBootnodes
	switch {
	case ctx.IsSet(BootnodesFlag.Name):
		urls = SplitAndTrim(ctx.String(BootnodesFlag.Name))
	}

	// don't apply defaults if BootstrapNodes is already set
	if cfg.BootstrapNodes != nil {
		return
	}

	cfg.BootstrapNodes = make([]*enode.Node, 0, len(urls))
	for _, url := range urls {
		if url != "" {
			node, err := enode.Parse(enode.ValidSchemes, url)
			if err != nil {
				log.Crit("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			cfg.BootstrapNodes = append(cfg.BootstrapNodes, node)
		}
	}
}

// setBootstrapNodesV5 creates a list of bootstrap nodes from the command line
// flags, reverting to pre-configured ones if none have been specified.
func setBootstrapNodesV5(ctx *cli.Context, cfg *p2p.Config) {
	urls := params.V5Bootnodes
	switch {
	case ctx.IsSet(BootnodesFlag.Name):
		urls = SplitAndTrim(ctx.String(BootnodesFlag.Name))
	case cfg.BootstrapNodesV5 != nil:
		return // already set, don't apply defaults.
	}

	cfg.BootstrapNodesV5 = make([]*enode.Node, 0, len(urls))
	for _, url := range urls {
		if url != "" {
			node, err := enode.Parse(enode.ValidSchemes, url)
			if err != nil {
				log.Error("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			cfg.BootstrapNodesV5 = append(cfg.BootstrapNodesV5, node)
		}
	}
}

// setListenAddress creates TCP/UDP listening address strings from set command
// line flags
func setListenAddress(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.IsSet(ListenPortFlag.Name) {
		cfg.ListenAddr = fmt.Sprintf(":%d", ctx.Int(ListenPortFlag.Name))
	}
	if ctx.IsSet(DiscoveryPortFlag.Name) {
		cfg.DiscAddr = fmt.Sprintf(":%d", ctx.Int(DiscoveryPortFlag.Name))
	}
}

// setNAT creates a port mapper from command line flags.
func setNAT(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.IsSet(NATFlag.Name) {
		natif, err := nat.Parse(ctx.String(NATFlag.Name))
		if err != nil {
			Fatalf("Option %s: %v", NATFlag.Name, err)
		}
		cfg.NAT = natif
	}
}

// SplitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func SplitAndTrim(input string) (ret []string) {
	l := strings.Split(input, ",")
	for _, r := range l {
		if r = strings.TrimSpace(r); r != "" {
			ret = append(ret, r)
		}
	}
	return ret
}

// setHTTP creates the HTTP RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setHTTP(ctx *cli.Context, cfg *node.Config) {
	if ctx.Bool(HTTPEnabledFlag.Name) && cfg.HTTPHost == "" {
		cfg.HTTPHost = "127.0.0.1"
		if ctx.IsSet(HTTPListenAddrFlag.Name) {
			cfg.HTTPHost = ctx.String(HTTPListenAddrFlag.Name)
		}
	}

	if ctx.IsSet(HTTPPortFlag.Name) {
		cfg.HTTPPort = ctx.Int(HTTPPortFlag.Name)
	}

	if ctx.IsSet(AuthListenFlag.Name) {
		cfg.AuthAddr = ctx.String(AuthListenFlag.Name)
	}

	if ctx.IsSet(AuthPortFlag.Name) {
		cfg.AuthPort = ctx.Int(AuthPortFlag.Name)
	}

	if ctx.IsSet(AuthVirtualHostsFlag.Name) {
		cfg.AuthVirtualHosts = SplitAndTrim(ctx.String(AuthVirtualHostsFlag.Name))
	}

	if ctx.IsSet(HTTPCORSDomainFlag.Name) {
		cfg.HTTPCors = SplitAndTrim(ctx.String(HTTPCORSDomainFlag.Name))
	}

	if ctx.IsSet(HTTPApiFlag.Name) {
		cfg.HTTPModules = SplitAndTrim(ctx.String(HTTPApiFlag.Name))
	}

	if ctx.IsSet(HTTPVirtualHostsFlag.Name) {
		cfg.HTTPVirtualHosts = SplitAndTrim(ctx.String(HTTPVirtualHostsFlag.Name))
	}

	if ctx.IsSet(HTTPPathPrefixFlag.Name) {
		cfg.HTTPPathPrefix = ctx.String(HTTPPathPrefixFlag.Name)
	}
}

// setGraphQL creates the GraphQL listener interface string from the set
// command line flags, returning empty if the GraphQL endpoint is disabled.
func setGraphQL(ctx *cli.Context, cfg *node.Config) {
	if ctx.IsSet(GraphQLCORSDomainFlag.Name) {
		cfg.GraphQLCors = SplitAndTrim(ctx.String(GraphQLCORSDomainFlag.Name))
	}
	if ctx.IsSet(GraphQLVirtualHostsFlag.Name) {
		cfg.GraphQLVirtualHosts = SplitAndTrim(ctx.String(GraphQLVirtualHostsFlag.Name))
	}
}

// setWS creates the WebSocket RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setWS(ctx *cli.Context, cfg *node.Config) {
	if ctx.Bool(WSEnabledFlag.Name) && cfg.WSHost == "" {
		cfg.WSHost = "127.0.0.1"
		if ctx.IsSet(WSListenAddrFlag.Name) {
			cfg.WSHost = ctx.String(WSListenAddrFlag.Name)
		}
	}
	if ctx.IsSet(WSPortFlag.Name) {
		cfg.WSPort = ctx.Int(WSPortFlag.Name)
	}

	if ctx.IsSet(WSAllowedOriginsFlag.Name) {
		cfg.WSOrigins = SplitAndTrim(ctx.String(WSAllowedOriginsFlag.Name))
	}

	if ctx.IsSet(WSApiFlag.Name) {
		cfg.WSModules = SplitAndTrim(ctx.String(WSApiFlag.Name))
	}

	if ctx.IsSet(WSPathPrefixFlag.Name) {
		cfg.WSPathPrefix = ctx.String(WSPathPrefixFlag.Name)
	}
}

// setIPC creates an IPC path configuration from the set command line flags,
// returning an empty string if IPC was explicitly disabled, or the set path.
func setIPC(ctx *cli.Context, cfg *node.Config) {
	CheckExclusive(ctx, IPCDisabledFlag, IPCPathFlag)
	switch {
	case ctx.Bool(IPCDisabledFlag.Name):
		cfg.IPCPath = ""
	case ctx.IsSet(IPCPathFlag.Name):
		cfg.IPCPath = ctx.String(IPCPathFlag.Name)
	}
}

// setLes configures the les server and ultra light client settings from the command line flags.
func setLes(ctx *cli.Context, cfg *tosconfig.Config) {
	if ctx.IsSet(LightServeFlag.Name) {
		cfg.LightServ = ctx.Int(LightServeFlag.Name)
	}
	if ctx.IsSet(LightIngressFlag.Name) {
		cfg.LightIngress = ctx.Int(LightIngressFlag.Name)
	}
	if ctx.IsSet(LightEgressFlag.Name) {
		cfg.LightEgress = ctx.Int(LightEgressFlag.Name)
	}
	if ctx.IsSet(LightMaxPeersFlag.Name) {
		cfg.LightPeers = ctx.Int(LightMaxPeersFlag.Name)
	}
	if ctx.IsSet(UltraLightServersFlag.Name) {
		cfg.UltraLightServers = strings.Split(ctx.String(UltraLightServersFlag.Name), ",")
	}
	if ctx.IsSet(UltraLightFractionFlag.Name) {
		cfg.UltraLightFraction = ctx.Int(UltraLightFractionFlag.Name)
	}
	if cfg.UltraLightFraction <= 0 && cfg.UltraLightFraction > 100 {
		log.Error("Ultra light fraction is invalid", "had", cfg.UltraLightFraction, "updated", tosconfig.Defaults.UltraLightFraction)
		cfg.UltraLightFraction = tosconfig.Defaults.UltraLightFraction
	}
	if ctx.IsSet(UltraLightOnlyAnnounceFlag.Name) {
		cfg.UltraLightOnlyAnnounce = ctx.Bool(UltraLightOnlyAnnounceFlag.Name)
	}
	if ctx.IsSet(LightNoPruneFlag.Name) {
		cfg.LightNoPrune = ctx.Bool(LightNoPruneFlag.Name)
	}
	if ctx.IsSet(LightNoSyncServeFlag.Name) {
		cfg.LightNoSyncServe = ctx.Bool(LightNoSyncServeFlag.Name)
	}
}

// MakeDatabaseHandles raises out the number of allowed file handles per process
// for GTOS and returns half of the allowance to assign to the database.
func MakeDatabaseHandles(max int) int {
	limit, err := fdlimit.Maximum()
	if err != nil {
		Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	}
	switch {
	case max == 0:
		// User didn't specify a meaningful value, use system limits
	case max < 128:
		// User specified something unhealthy, just use system defaults
		log.Error("File descriptor limit invalid (<128)", "had", max, "updated", limit)
	case max > limit:
		// User requested more than the OS allows, notify that we can't allocate it
		log.Warn("Requested file descriptors denied by OS", "req", max, "limit", limit)
	default:
		// User limit is meaningful and within allowed range, use that
		limit = max
	}
	raised, err := fdlimit.Raise(uint64(limit))
	if err != nil {
		Fatalf("Failed to raise file descriptor allowance: %v", err)
	}
	return int(raised / 2) // Leave half for networking and other stuff
}

// MakeAddress converts an account specified directly as a hex encoded string or
// a key index in the key store to an internal account representation.
func MakeAddress(ks *keystore.KeyStore, account string) (accounts.Account, error) {
	// If the specified account is a valid address, return it
	if common.IsHexAddress(account) {
		return accounts.Account{Address: common.HexToAddress(account)}, nil
	}
	// Otherwise try to interpret the account as a keystore index
	index, err := strconv.Atoi(account)
	if err != nil || index < 0 {
		return accounts.Account{}, fmt.Errorf("invalid account address or index %q", account)
	}
	log.Warn("-------------------------------------------------------------------")
	log.Warn("Referring to accounts by order in the keystore folder is dangerous!")
	log.Warn("This functionality is deprecated and will be removed in the future!")
	log.Warn("Please use explicit addresses! (can search via `gtos account list`)")
	log.Warn("-------------------------------------------------------------------")

	accs := ks.Accounts()
	if len(accs) <= index {
		return accounts.Account{}, fmt.Errorf("index %d higher than number of accounts %d", index, len(accs))
	}
	return accs[index], nil
}

// setCoinbase retrieves the coinbase either from the directly specified
// command line flags or from the keystore if CLI indexed.
func setCoinbase(ctx *cli.Context, ks *keystore.KeyStore, cfg *tosconfig.Config) {
	// Extract the current coinbase
	var coinbase string
	if ctx.IsSet(MinerCoinbaseFlag.Name) {
		coinbase = ctx.String(MinerCoinbaseFlag.Name)
	}
	// Convert the coinbase into an address and configure it.
	if coinbase != "" {
		if ks != nil {
			account, err := MakeAddress(ks, coinbase)
			if err != nil {
				Fatalf("Invalid miner coinbase: %v", err)
			}
			cfg.Miner.Coinbase = account.Address
			cfg.Miner.Tosbase = account.Address // keep deprecated alias in sync
		} else {
			Fatalf("No coinbase configured")
		}
	}
}

// setTosbase is a deprecated alias for setCoinbase.
func setTosbase(ctx *cli.Context, ks *keystore.KeyStore, cfg *tosconfig.Config) {
	setCoinbase(ctx, ks, cfg)
}

// MakePasswordList reads password lines from the file specified by the global --password flag.
func MakePasswordList(ctx *cli.Context) []string {
	path := ctx.Path(PasswordFileFlag.Name)
	if path == "" {
		return nil
	}
	text, err := os.ReadFile(path)
	if err != nil {
		Fatalf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

func SetP2PConfig(ctx *cli.Context, cfg *p2p.Config) {
	setNodeKey(ctx, cfg)
	setNAT(ctx, cfg)
	setListenAddress(ctx, cfg)
	setBootstrapNodes(ctx, cfg)
	setBootstrapNodesV5(ctx, cfg)

	lightClient := ctx.String(SyncModeFlag.Name) == "light"
	lightServer := (ctx.Int(LightServeFlag.Name) != 0)

	lightPeers := ctx.Int(LightMaxPeersFlag.Name)
	if lightClient && !ctx.IsSet(LightMaxPeersFlag.Name) {
		// dynamic default - for clients we use 1/10th of the default for servers
		lightPeers /= 10
	}

	if ctx.IsSet(MaxPeersFlag.Name) {
		cfg.MaxPeers = ctx.Int(MaxPeersFlag.Name)
		if lightServer && !ctx.IsSet(LightMaxPeersFlag.Name) {
			cfg.MaxPeers += lightPeers
		}
	} else {
		if lightServer {
			cfg.MaxPeers += lightPeers
		}
		if lightClient && ctx.IsSet(LightMaxPeersFlag.Name) && cfg.MaxPeers < lightPeers {
			cfg.MaxPeers = lightPeers
		}
	}
	if !(lightClient || lightServer) {
		lightPeers = 0
	}
	tosPeers := cfg.MaxPeers - lightPeers
	if lightClient {
		tosPeers = 0
	}
	log.Info("Maximum peer count", "TOS", tosPeers, "LES", lightPeers, "total", cfg.MaxPeers)

	if ctx.IsSet(MaxPendingPeersFlag.Name) {
		cfg.MaxPendingPeers = ctx.Int(MaxPendingPeersFlag.Name)
	}
	if ctx.IsSet(NoDiscoverFlag.Name) || lightClient {
		cfg.NoDiscovery = true
	}

	// if we're running a light client or server, force enable the v5 peer discovery
	// unless it is explicitly disabled with --nodiscover note that explicitly specifying
	// --v5disc overrides --nodiscover, in which case the later only disables v4 discovery
	forceV5Discovery := (lightClient || lightServer) && !ctx.Bool(NoDiscoverFlag.Name)
	if ctx.IsSet(DiscoveryV5Flag.Name) {
		cfg.DiscoveryV5 = ctx.Bool(DiscoveryV5Flag.Name)
	} else if forceV5Discovery {
		cfg.DiscoveryV5 = true
	}

	if netrestrict := ctx.String(NetrestrictFlag.Name); netrestrict != "" {
		list, err := netutil.ParseNetlist(netrestrict)
		if err != nil {
			Fatalf("Option %q: %v", NetrestrictFlag.Name, err)
		}
		cfg.NetRestrict = list
	}

	if ctx.Bool(DeveloperFlag.Name) {
		// --dev mode can't use p2p networking.
		cfg.MaxPeers = 0
		cfg.ListenAddr = ""
		cfg.NoDial = true
		cfg.NoDiscovery = true
		cfg.DiscoveryV5 = false
	}
}

// SetNodeConfig applies node-related command line flags to the config.
func SetNodeConfig(ctx *cli.Context, cfg *node.Config) {
	SetP2PConfig(ctx, &cfg.P2P)
	setIPC(ctx, cfg)
	setHTTP(ctx, cfg)
	setGraphQL(ctx, cfg)
	setWS(ctx, cfg)
	setNodeUserIdent(ctx, cfg)
	SetDataDir(ctx, cfg)

	if ctx.IsSet(JWTSecretFlag.Name) {
		cfg.JWTSecret = ctx.String(JWTSecretFlag.Name)
	}

	if ctx.IsSet(KeyStoreDirFlag.Name) {
		cfg.KeyStoreDir = ctx.String(KeyStoreDirFlag.Name)
	}
	if ctx.IsSet(DeveloperFlag.Name) {
		cfg.UseLightweightKDF = true
	}
	if ctx.IsSet(LightKDFFlag.Name) {
		cfg.UseLightweightKDF = ctx.Bool(LightKDFFlag.Name)
	}
	if ctx.IsSet(InsecureUnlockAllowedFlag.Name) {
		cfg.InsecureUnlockAllowed = ctx.Bool(InsecureUnlockAllowedFlag.Name)
	}
}

func SetDataDir(ctx *cli.Context, cfg *node.Config) {
	switch {
	case ctx.IsSet(DataDirFlag.Name):
		cfg.DataDir = ctx.String(DataDirFlag.Name)
	case ctx.Bool(DeveloperFlag.Name):
		cfg.DataDir = "" // unless explicitly requested, use memory databases
	}
}

func setTxPool(ctx *cli.Context, cfg *core.TxPoolConfig) {
	if ctx.IsSet(TxPoolLocalsFlag.Name) {
		locals := strings.Split(ctx.String(TxPoolLocalsFlag.Name), ",")
		for _, account := range locals {
			if trimmed := strings.TrimSpace(account); !common.IsHexAddress(trimmed) {
				Fatalf("Invalid account in --txpool.locals: %s", trimmed)
			} else {
				cfg.Locals = append(cfg.Locals, common.HexToAddress(account))
			}
		}
	}
	if ctx.IsSet(TxPoolNoLocalsFlag.Name) {
		cfg.NoLocals = ctx.Bool(TxPoolNoLocalsFlag.Name)
	}
	if ctx.IsSet(TxPoolJournalFlag.Name) {
		cfg.Journal = ctx.String(TxPoolJournalFlag.Name)
	}
	if ctx.IsSet(TxPoolRejournalFlag.Name) {
		cfg.Rejournal = ctx.Duration(TxPoolRejournalFlag.Name)
	}
	if ctx.IsSet(TxPoolPriceLimitFlag.Name) {
		cfg.PriceLimit = ctx.Uint64(TxPoolPriceLimitFlag.Name)
	}
	if ctx.IsSet(TxPoolPriceBumpFlag.Name) {
		cfg.PriceBump = ctx.Uint64(TxPoolPriceBumpFlag.Name)
	}
	if ctx.IsSet(TxPoolAccountSlotsFlag.Name) {
		cfg.AccountSlots = ctx.Uint64(TxPoolAccountSlotsFlag.Name)
	}
	if ctx.IsSet(TxPoolGlobalSlotsFlag.Name) {
		cfg.GlobalSlots = ctx.Uint64(TxPoolGlobalSlotsFlag.Name)
	}
	if ctx.IsSet(TxPoolAccountQueueFlag.Name) {
		cfg.AccountQueue = ctx.Uint64(TxPoolAccountQueueFlag.Name)
	}
	if ctx.IsSet(TxPoolGlobalQueueFlag.Name) {
		cfg.GlobalQueue = ctx.Uint64(TxPoolGlobalQueueFlag.Name)
	}
	if ctx.IsSet(TxPoolLifetimeFlag.Name) {
		cfg.Lifetime = ctx.Duration(TxPoolLifetimeFlag.Name)
	}
}

func setMiner(ctx *cli.Context, cfg *miner.Config) {
	if ctx.IsSet(MinerNotifyFlag.Name) {
		cfg.Notify = strings.Split(ctx.String(MinerNotifyFlag.Name), ",")
	}
	cfg.NotifyFull = ctx.Bool(MinerNotifyFullFlag.Name)
	if ctx.IsSet(MinerExtraDataFlag.Name) {
		cfg.ExtraData = []byte(ctx.String(MinerExtraDataFlag.Name))
	}
	if ctx.IsSet(MinerGasLimitFlag.Name) {
		cfg.GasCeil = ctx.Uint64(MinerGasLimitFlag.Name)
	}
	if ctx.IsSet(MinerRecommitIntervalFlag.Name) {
		cfg.Recommit = ctx.Duration(MinerRecommitIntervalFlag.Name)
	}
	if ctx.IsSet(MinerNoVerifyFlag.Name) {
		cfg.Noverify = ctx.Bool(MinerNoVerifyFlag.Name)
	}
	if ctx.IsSet(LegacyMinerGasTargetFlag.Name) {
		log.Warn("The generic --miner.gastarget flag is deprecated and will be removed in the future!")
	}
}

func setRequiredBlocks(ctx *cli.Context, cfg *tosconfig.Config) {
	requiredBlocks := ctx.String(TOSRequiredBlocksFlag.Name)
	if requiredBlocks == "" {
		if ctx.IsSet(LegacyWhitelistFlag.Name) {
			log.Warn("The flag --whitelist is deprecated and will be removed, please use --tos.requiredblocks")
			requiredBlocks = ctx.String(LegacyWhitelistFlag.Name)
		} else {
			return
		}
	}
	cfg.RequiredBlocks = make(map[uint64]common.Hash)
	for _, entry := range strings.Split(requiredBlocks, ",") {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			Fatalf("Invalid required block entry: %s", entry)
		}
		number, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			Fatalf("Invalid required block number %s: %v", parts[0], err)
		}
		var hash common.Hash
		if err = hash.UnmarshalText([]byte(parts[1])); err != nil {
			Fatalf("Invalid required block hash %s: %v", parts[1], err)
		}
		cfg.RequiredBlocks[number] = hash
	}
}

// CheckExclusive verifies that only a single instance of the provided flags was
// set by the user. Each flag might optionally be followed by a string type to
// specialize it further.
func CheckExclusive(ctx *cli.Context, args ...interface{}) {
	set := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		// Make sure the next argument is a flag and skip if not set
		flag, ok := args[i].(cli.Flag)
		if !ok {
			panic(fmt.Sprintf("invalid argument, not cli.Flag type: %T", args[i]))
		}
		// Check if next arg extends current and expand its name if so
		name := flag.Names()[0]

		if i+1 < len(args) {
			switch option := args[i+1].(type) {
			case string:
				// Extended flag check, make sure value set doesn't conflict with passed in option
				if ctx.String(flag.Names()[0]) == option {
					name += "=" + option
					set = append(set, "--"+name)
				}
				// shift arguments and continue
				i++
				continue

			case cli.Flag:
			default:
				panic(fmt.Sprintf("invalid argument, not cli.Flag or string extension: %T", args[i+1]))
			}
		}
		// Mark the flag if it's set
		if ctx.IsSet(flag.Names()[0]) {
			set = append(set, "--"+name)
		}
	}
	if len(set) > 1 {
		Fatalf("Flags %v can't be used at the same time", strings.Join(set, ", "))
	}
}

func resolveDeveloperPeriodMs(ctx *cli.Context) uint64 {
	if ctx.IsSet(DeveloperPeriodMsFlag.Name) {
		return ctx.Uint64(DeveloperPeriodMsFlag.Name)
	}
	if ctx.IsSet(DeveloperPeriodFlag.Name) {
		return uint64(ctx.Int(DeveloperPeriodFlag.Name)) * 1000
	}
	return ctx.Uint64(DeveloperPeriodMsFlag.Name)
}

// SetTOSConfig applies tos-related command line flags to the config.
func SetTOSConfig(ctx *cli.Context, stack *node.Node, cfg *tosconfig.Config) {
	// Avoid conflicting network flags
	CheckExclusive(ctx, MainnetFlag, DeveloperFlag)
	CheckExclusive(ctx, LightServeFlag, SyncModeFlag, "light")
	if ctx.String(GCModeFlag.Name) == "archive" && ctx.Uint64(TxLookupLimitFlag.Name) != 0 {
		ctx.Set(TxLookupLimitFlag.Name, "0")
		log.Warn("Disable transaction unindexing for archive node")
	}
	if ctx.IsSet(LightServeFlag.Name) && ctx.Uint64(TxLookupLimitFlag.Name) != 0 {
		log.Warn("LES server cannot serve old transaction status and cannot connect below les/4 protocol version if transaction lookup index is limited")
	}
	var ks *keystore.KeyStore
	if keystores := stack.AccountManager().Backends(keystore.KeyStoreType); len(keystores) > 0 {
		ks = keystores[0].(*keystore.KeyStore)
	}
	setCoinbase(ctx, ks, cfg)
	setTxPool(ctx, &cfg.TxPool)
	setMiner(ctx, &cfg.Miner)
	setRequiredBlocks(ctx, cfg)
	setLes(ctx, cfg)

	// Cap the cache allowance and tune the garbage collector
	mem, err := gopsutil.VirtualMemory()
	if err == nil {
		if 32<<(^uintptr(0)>>63) == 32 && mem.Total > 2*1024*1024*1024 {
			log.Warn("Lowering memory allowance on 32bit arch", "available", mem.Total/1024/1024, "addressable", 2*1024)
			mem.Total = 2 * 1024 * 1024 * 1024
		}
		allowance := int(mem.Total / 1024 / 1024 / 3)
		if cache := ctx.Int(CacheFlag.Name); cache > allowance {
			log.Warn("Sanitizing cache to Go's GC limits", "provided", cache, "updated", allowance)
			ctx.Set(CacheFlag.Name, strconv.Itoa(allowance))
		}
	}
	// Ensure Go's GC ignores the database cache for trigger percentage
	cache := ctx.Int(CacheFlag.Name)
	gogc := math.Max(20, math.Min(100, 100/(float64(cache)/1024)))

	log.Debug("Sanitizing Go's GC trigger", "percent", int(gogc))
	godebug.SetGCPercent(int(gogc))

	if ctx.IsSet(SyncModeFlag.Name) {
		cfg.SyncMode = *flags.GlobalTextMarshaler(ctx, SyncModeFlag.Name).(*downloader.SyncMode)
	}
	if ctx.IsSet(NetworkIdFlag.Name) {
		cfg.NetworkId = ctx.Uint64(NetworkIdFlag.Name)
	}
	if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheDatabaseFlag.Name) {
		cfg.DatabaseCache = ctx.Int(CacheFlag.Name) * ctx.Int(CacheDatabaseFlag.Name) / 100
	}
	cfg.DatabaseHandles = MakeDatabaseHandles(ctx.Int(FDLimitFlag.Name))
	if ctx.IsSet(AncientFlag.Name) {
		cfg.DatabaseFreezer = ctx.String(AncientFlag.Name)
	}

	if gcmode := ctx.String(GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", GCModeFlag.Name)
	}
	if ctx.IsSet(GCModeFlag.Name) {
		cfg.NoPruning = ctx.String(GCModeFlag.Name) == "archive"
	}
	if ctx.IsSet(CacheNoPrefetchFlag.Name) {
		cfg.NoPrefetch = ctx.Bool(CacheNoPrefetchFlag.Name)
	}
	// Read the value from the flag no matter if it's set or not.
	cfg.Preimages = ctx.Bool(CachePreimagesFlag.Name)
	if cfg.NoPruning && !cfg.Preimages {
		cfg.Preimages = true
		log.Info("Enabling recording of key preimages since archive mode is used")
	}
	if ctx.IsSet(TxLookupLimitFlag.Name) {
		cfg.TxLookupLimit = ctx.Uint64(TxLookupLimitFlag.Name)
	}
	if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheTrieFlag.Name) {
		cfg.TrieCleanCache = ctx.Int(CacheFlag.Name) * ctx.Int(CacheTrieFlag.Name) / 100
	}
	if ctx.IsSet(CacheTrieJournalFlag.Name) {
		cfg.TrieCleanCacheJournal = ctx.String(CacheTrieJournalFlag.Name)
	}
	if ctx.IsSet(CacheTrieRejournalFlag.Name) {
		cfg.TrieCleanCacheRejournal = ctx.Duration(CacheTrieRejournalFlag.Name)
	}
	if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheGCFlag.Name) {
		cfg.TrieDirtyCache = ctx.Int(CacheFlag.Name) * ctx.Int(CacheGCFlag.Name) / 100
	}
	if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheSnapshotFlag.Name) {
		cfg.SnapshotCache = ctx.Int(CacheFlag.Name) * ctx.Int(CacheSnapshotFlag.Name) / 100
	}
	if ctx.IsSet(CacheLogSizeFlag.Name) {
		cfg.FilterLogCacheSize = ctx.Int(CacheLogSizeFlag.Name)
	}
	if !ctx.Bool(SnapshotFlag.Name) {
		// If snap-sync is requested, this flag is also required
		if cfg.SyncMode == downloader.SnapSync {
			log.Info("Snap sync requested, enabling --snapshot")
		} else {
			cfg.TrieCleanCache += cfg.SnapshotCache
			cfg.SnapshotCache = 0 // Disabled
		}
	}
	if ctx.IsSet(DocRootFlag.Name) {
		cfg.DocRoot = ctx.String(DocRootFlag.Name)
	}
	if ctx.IsSet(VMEnableDebugFlag.Name) {
		// TODO(fjl): force-enable this in --dev mode
		cfg.EnablePreimageRecording = ctx.Bool(VMEnableDebugFlag.Name)
	}

	if ctx.IsSet(RPCGlobalGasCapFlag.Name) {
		cfg.RPCGasCap = ctx.Uint64(RPCGlobalGasCapFlag.Name)
	}
	if cfg.RPCGasCap != 0 {
		log.Info("Set global gas cap", "cap", cfg.RPCGasCap)
	} else {
		log.Info("Global gas cap disabled")
	}
	if ctx.IsSet(RPCGlobalEVMTimeoutFlag.Name) {
		cfg.RPCEVMTimeout = ctx.Duration(RPCGlobalEVMTimeoutFlag.Name)
	}
	if ctx.IsSet(RPCGlobalTxFeeCapFlag.Name) {
		cfg.RPCTxFeeCap = ctx.Float64(RPCGlobalTxFeeCapFlag.Name)
	}
	if ctx.IsSet(NoDiscoverFlag.Name) {
		cfg.TosDiscoveryURLs, cfg.SnapDiscoveryURLs = []string{}, []string{}
	} else if ctx.IsSet(DNSDiscoveryFlag.Name) {
		urls := ctx.String(DNSDiscoveryFlag.Name)
		if urls == "" {
			cfg.TosDiscoveryURLs = []string{}
		} else {
			cfg.TosDiscoveryURLs = SplitAndTrim(urls)
		}
	}
	// Override any default configs for hard coded networks.
	switch {
	case ctx.Bool(MainnetFlag.Name):
		if !ctx.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 1
		}
		cfg.Genesis = core.DefaultGenesisBlock()
		SetDNSDiscoveryDefaults(cfg, params.MainnetGenesisHash)
	case ctx.Bool(DeveloperFlag.Name):
		if !ctx.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 1337
		}
		cfg.SyncMode = downloader.FullSync
		// Create new developer account or reuse existing one
		var (
			developer  accounts.Account
			passphrase string
			err        error
		)
		if list := MakePasswordList(ctx); len(list) > 0 {
			// Just take the first value. Although the function returns a possible multiple values and
			// some usages iterate through them as attempts, that doesn't make sense in this setting,
			// when we're definitely concerned with only one account.
			passphrase = list[0]
		}
		// setCoinbase has been called above, configuring the miner address from command line flags.
		if cfg.Miner.Coinbase != (common.Address{}) {
			developer = accounts.Account{Address: cfg.Miner.Coinbase}
		} else if accs := ks.Accounts(); len(accs) > 0 {
			developer = ks.Accounts()[0]
		} else {
			developer, err = ks.NewAccount(passphrase)
			if err != nil {
				Fatalf("Failed to create developer account: %v", err)
			}
		}
		if err := ks.Unlock(developer, passphrase); err != nil {
			Fatalf("Failed to unlock developer account: %v", err)
		}
		log.Info("Using developer account", "address", developer.Address)

		// Create a new developer genesis block or reuse existing one
		periodMs := resolveDeveloperPeriodMs(ctx)
		cfg.Genesis = core.DeveloperGenesisBlockMs(periodMs, ctx.Uint64(DeveloperGasLimitFlag.Name), developer.Address)
		if ctx.IsSet(DataDirFlag.Name) {
			// If datadir doesn't exist we need to open db in write-mode
			// so leveldb can create files.
			readonly := true
			if !common.FileExist(stack.ResolvePath("chaindata")) {
				readonly = false
			}
			// Check if we have an already initialized chain and fall back to
			// that if so. Otherwise we need to generate a new genesis spec.
			chaindb := MakeChainDatabase(ctx, stack, readonly)
			if rawdb.ReadCanonicalHash(chaindb, 0) != (common.Hash{}) {
				cfg.Genesis = nil // fallback to db content
			}
			chaindb.Close()
		}
	default:
		if cfg.NetworkId == 1 {
			SetDNSDiscoveryDefaults(cfg, params.MainnetGenesisHash)
		}
	}
}

// SetDNSDiscoveryDefaults configures DNS discovery with the given URL if
// no URLs are set.
func SetDNSDiscoveryDefaults(cfg *tosconfig.Config, genesis common.Hash) {
	if cfg.TosDiscoveryURLs != nil {
		return // already set through flags/config
	}
	protocol := "all"
	if cfg.SyncMode == downloader.LightSync {
		protocol = "les"
	}
	if url := params.KnownDNSNetwork(genesis, protocol); url != "" {
		cfg.TosDiscoveryURLs = []string{url}
		cfg.SnapDiscoveryURLs = cfg.TosDiscoveryURLs
	}
}

// RegisterTOSService adds an TOS client to the stack.
// The second return value is the full node instance, which may be nil if the
// node is running as a light client.
func RegisterTOSService(stack *node.Node, cfg *tosconfig.Config) (tosapi.Backend, *tos.TOS) {
	if cfg.SyncMode == downloader.LightSync {
		Fatalf("light sync mode is not supported in gtos consensus-layer profile")
	}
	backend, err := tos.New(stack, cfg)
	if err != nil {
		Fatalf("Failed to register the TOS service: %v", err)
	}
	if cfg.LightServ > 0 {
		log.Warn("Ignoring light server setting in gtos consensus-layer profile", "light.serve", cfg.LightServ)
	}
	return backend.APIBackend, backend
}

// RegisterTOSStatsService configures the TOS Stats daemon and adds it to the node.
func RegisterTOSStatsService(stack *node.Node, backend tosapi.Backend, url string) {
	log.Warn("Ignoring tosstats setting in gtos consensus-layer profile", "url", url)
}

// RegisterGraphQLService is a no-op stub: GraphQL has been removed from GTOS.
func RegisterGraphQLService(stack *node.Node, backend tosapi.Backend, filterSystem *filters.FilterSystem, cfg *node.Config) {
	// GraphQL service removed; graphql/ directory was deleted as part of TVM removal.
}

// RegisterFilterAPI adds the tos log filtering RPC API to the node.
func RegisterFilterAPI(stack *node.Node, backend tosapi.Backend, ethcfg *tosconfig.Config) *filters.FilterSystem {
	isLightClient := ethcfg.SyncMode == downloader.LightSync
	filterSystem := filters.NewFilterSystem(backend, filters.Config{
		LogCacheSize: ethcfg.FilterLogCacheSize,
	})
	stack.RegisterAPIs([]rpc.API{{
		Namespace: "tos",
		Service:   filters.NewFilterAPI(filterSystem, isLightClient),
	}})
	return filterSystem
}

func SetupMetrics(ctx *cli.Context) {
	if metrics.Enabled {
		log.Info("Enabling metrics collection")

		var (
			enableExport   = ctx.Bool(MetricsEnableInfluxDBFlag.Name)
			enableExportV2 = ctx.Bool(MetricsEnableInfluxDBV2Flag.Name)
		)

		if enableExport || enableExportV2 {
			CheckExclusive(ctx, MetricsEnableInfluxDBFlag, MetricsEnableInfluxDBV2Flag)

			v1FlagIsSet := ctx.IsSet(MetricsInfluxDBUsernameFlag.Name) ||
				ctx.IsSet(MetricsInfluxDBPasswordFlag.Name)

			v2FlagIsSet := ctx.IsSet(MetricsInfluxDBTokenFlag.Name) ||
				ctx.IsSet(MetricsInfluxDBOrganizationFlag.Name) ||
				ctx.IsSet(MetricsInfluxDBBucketFlag.Name)

			if enableExport && v2FlagIsSet {
				Fatalf("Flags --influxdb.metrics.organization, --influxdb.metrics.token, --influxdb.metrics.bucket are only available for influxdb-v2")
			} else if enableExportV2 && v1FlagIsSet {
				Fatalf("Flags --influxdb.metrics.username, --influxdb.metrics.password are only available for influxdb-v1")
			}
		}

		var (
			endpoint = ctx.String(MetricsInfluxDBEndpointFlag.Name)
			database = ctx.String(MetricsInfluxDBDatabaseFlag.Name)
			username = ctx.String(MetricsInfluxDBUsernameFlag.Name)
			password = ctx.String(MetricsInfluxDBPasswordFlag.Name)

			token        = ctx.String(MetricsInfluxDBTokenFlag.Name)
			bucket       = ctx.String(MetricsInfluxDBBucketFlag.Name)
			organization = ctx.String(MetricsInfluxDBOrganizationFlag.Name)
		)

		if enableExport {
			tagsMap := SplitTagsFlag(ctx.String(MetricsInfluxDBTagsFlag.Name))

			log.Info("Enabling metrics export to InfluxDB")

			go influxdb.InfluxDBWithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, database, username, password, "gtos.", tagsMap)
		} else if enableExportV2 {
			tagsMap := SplitTagsFlag(ctx.String(MetricsInfluxDBTagsFlag.Name))

			log.Info("Enabling metrics export to InfluxDB (v2)")

			go influxdb.InfluxDBV2WithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, token, bucket, organization, "gtos.", tagsMap)
		}

		if ctx.IsSet(MetricsHTTPFlag.Name) {
			address := fmt.Sprintf("%s:%d", ctx.String(MetricsHTTPFlag.Name), ctx.Int(MetricsPortFlag.Name))
			log.Info("Enabling stand-alone metrics HTTP endpoint", "address", address)
			exp.Setup(address)
		}
	}
}

func SplitTagsFlag(tagsFlag string) map[string]string {
	tags := strings.Split(tagsFlag, ",")
	tagsMap := map[string]string{}

	for _, t := range tags {
		if t != "" {
			kv := strings.Split(t, "=")

			if len(kv) == 2 {
				tagsMap[kv[0]] = kv[1]
			}
		}
	}

	return tagsMap
}

// MakeChainDatabase open an LevelDB using the flags passed to the client and will hard crash if it fails.
func MakeChainDatabase(ctx *cli.Context, stack *node.Node, readonly bool) tosdb.Database {
	var (
		cache   = ctx.Int(CacheFlag.Name) * ctx.Int(CacheDatabaseFlag.Name) / 100
		handles = MakeDatabaseHandles(ctx.Int(FDLimitFlag.Name))

		err     error
		chainDb tosdb.Database
	)
	switch {
	case ctx.IsSet(RemoteDBFlag.Name):
		log.Info("Using remote db", "url", ctx.String(RemoteDBFlag.Name))
		chainDb, err = remotedb.New(ctx.String(RemoteDBFlag.Name))
	case ctx.String(SyncModeFlag.Name) == "light":
		chainDb, err = stack.OpenDatabase("lightchaindata", cache, handles, "", readonly)
	default:
		chainDb, err = stack.OpenDatabaseWithFreezer("chaindata", cache, handles, ctx.String(AncientFlag.Name), "", readonly)
	}
	if err != nil {
		Fatalf("Could not open database: %v", err)
	}
	return chainDb
}

func MakeGenesis(ctx *cli.Context) *core.Genesis {
	var genesis *core.Genesis
	switch {
	case ctx.Bool(MainnetFlag.Name):
		genesis = core.DefaultGenesisBlock()
	case ctx.Bool(DeveloperFlag.Name):
		Fatalf("Developer chains are ephemeral")
	}
	return genesis
}

// MakeChain creates a chain manager from set command line flags.
func MakeChain(ctx *cli.Context, stack *node.Node) (chain *core.BlockChain, chainDb tosdb.Database) {
	var err error
	chainDb = MakeChainDatabase(ctx, stack, false) // TODO(rjl493456442) support read-only database
	config, _, err := core.SetupGenesisBlock(chainDb, MakeGenesis(ctx))
	if err != nil {
		Fatalf("%v", err)
	}

	engine := tosconfig.CreateConsensusEngine(stack, config, chainDb)
	if gcmode := ctx.String(GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", GCModeFlag.Name)
	}
	cache := &core.CacheConfig{
		TrieCleanLimit:      tosconfig.Defaults.TrieCleanCache,
		TrieCleanNoPrefetch: ctx.Bool(CacheNoPrefetchFlag.Name),
		TrieDirtyLimit:      tosconfig.Defaults.TrieDirtyCache,
		TrieDirtyDisabled:   ctx.String(GCModeFlag.Name) == "archive",
		TrieTimeLimit:       tosconfig.Defaults.TrieTimeout,
		SnapshotLimit:       tosconfig.Defaults.SnapshotCache,
		Preimages:           ctx.Bool(CachePreimagesFlag.Name),
	}
	if cache.TrieDirtyDisabled && !cache.Preimages {
		cache.Preimages = true
		log.Info("Enabling recording of key preimages since archive mode is used")
	}
	if !ctx.Bool(SnapshotFlag.Name) {
		cache.SnapshotLimit = 0 // Disabled
	}
	if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheTrieFlag.Name) {
		cache.TrieCleanLimit = ctx.Int(CacheFlag.Name) * ctx.Int(CacheTrieFlag.Name) / 100
	}
	if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheGCFlag.Name) {
		cache.TrieDirtyLimit = ctx.Int(CacheFlag.Name) * ctx.Int(CacheGCFlag.Name) / 100
	}
	// TODO(rjl493456442) disable snapshot generation/wiping if the chain is read only.
	// Disable transaction indexing/unindexing by default.
	chain, err = core.NewBlockChain(chainDb, cache, config, engine, nil, nil)
	if err != nil {
		Fatalf("Can't create BlockChain: %v", err)
	}
	return chain, chainDb
}

// MakeConsolePreloads retrieves the absolute paths for the console JavaScript
// scripts to preload before starting.
func MakeConsolePreloads(ctx *cli.Context) []string {
	// Skip preloading if there's nothing to preload
	if ctx.String(PreloadJSFlag.Name) == "" {
		return nil
	}
	// Otherwise resolve absolute paths and return them
	var preloads []string

	for _, file := range strings.Split(ctx.String(PreloadJSFlag.Name), ",") {
		preloads = append(preloads, strings.TrimSpace(file))
	}
	return preloads
}
