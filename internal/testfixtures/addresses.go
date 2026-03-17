package testfixtures

import "github.com/tos-network/gtos/common"

const (
	Secp256k1KeyAHex = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
	Secp256k1KeyBHex = "8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a"
	Secp256k1KeyCHex = "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee"

	Secp256k1AddrAHex = "0xA448f24C6D18e575453Db13171562B71999873Db5B286DF957Af199EC94617F7"
	Secp256k1AddrBHex = "0x98f22927e77F755E1c92c585703C4B2BD70c169F5717101cAEE543299fC946C7"
	Secp256k1AddrCHex = "0x6469CC2093f39e9117071E660d3Ab14BBaD3D99f4203BD7A11Acb94882050E7E"
)

var (
	Secp256k1AddrA = common.HexToAddress(Secp256k1AddrAHex)
	Secp256k1AddrB = common.HexToAddress(Secp256k1AddrBHex)
	Secp256k1AddrC = common.HexToAddress(Secp256k1AddrCHex)
)
