package core

import lua "github.com/tos-network/glua"

// luaBuiltinModules maps module names to pre-compiled bytecode.
// Compiled once at package init from the Lua source constants below.
// Loaded via tos.import("moduleName") inside contract scripts.
var luaBuiltinModules map[string][]byte

func init() {
	luaBuiltinModules = make(map[string][]byte, 4)
	for name, src := range map[string]string{
		"tos20":    tos20LuaSrc,
		"tos721":   tos721LuaSrc,
		"access":   accessLuaSrc,
		"timelock": timelockLuaSrc,
	} {
		bc, err := lua.CompileSourceToBytecode([]byte(src), name)
		if err != nil {
			panic("lua_stdlib: failed to pre-compile module " + name + ": " + err.Error())
		}
		luaBuiltinModules[name] = bc
	}
}

// tos20LuaSrc is the TOS-20 token standard — a pure-Lua ERC-20 equivalent.
//
// Usage inside a contract:
//
//	local T = tos.import("tos20")
//	T.init("MyToken", "MTK", 18, 1000000)
//	tos.dispatch(T.handlers)
//
// T.init(name, symbol, decimals, initialSupply)
//
//	Registers an oncreate hook that, on the contract's first call:
//	  - stores name/symbol/decimals
//	  - mints initialSupply to tos.caller
//	  - emits Transfer(ZERO_ADDRESS → caller, initialSupply)
//
// T.handlers  — pass directly to tos.dispatch(); implements:
//
//	name()                              → string
//	symbol()                            → string
//	decimals()                          → uint8
//	totalSupply()                       → uint256
//	balanceOf(address)                  → uint256
//	allowance(address,address)          → uint256
//	transfer(address,uint256)           → bool
//	approve(address,uint256)            → bool
//	transferFrom(address,address,uint256) → bool
//	fallback                            → revert "TOS20: unknown selector"
//
// Storage keys (all prefixed with "_" to avoid collision with user keys):
//
//	_name, _symbol  — tos.getStr / tos.setStr
//	_decimals, _supply — tos.get / tos.set
//	_bal            — tos.mapGet/mapSet("_bal", address)
//	_allow          — tos.mapGet/mapSet("_allow", owner, spender)
const tos20LuaSrc = `
local M = {}

function M.init(name, symbol, decimals, initialSupply)
    tos.oncreate(function()
        tos.setStr("_name",    name)
        tos.setStr("_symbol",  symbol)
        tos.set("_decimals",   decimals)
        if initialSupply > 0 then
            local owner = tos.caller
            tos.mapSet("_bal", owner, initialSupply)
            tos.set("_supply", initialSupply)
            tos.emit("Transfer",
                "address indexed", tos.ZERO_ADDRESS,
                "address indexed", owner,
                "uint256",         initialSupply)
        end
    end)
end

local function _bal(addr)
    return tos.mapGet("_bal", addr) or 0
end

local function _allow(owner, spender)
    return tos.mapGet("_allow", owner, spender) or 0
end

local function _transfer(from, to, amount)
    require(tos.isAddress(to),      "TOS20: invalid recipient")
    require(to ~= tos.ZERO_ADDRESS, "TOS20: transfer to zero address")
    local fromBal = _bal(from)
    require(fromBal >= amount, "TOS20: insufficient balance")
    tos.mapSet("_bal", from, fromBal - amount)
    tos.mapSet("_bal", to, _bal(to) + amount)
    tos.emit("Transfer",
        "address indexed", from,
        "address indexed", to,
        "uint256",         amount)
end

M.handlers = {
    ["name()"] = function()
        tos.result("string", tos.getStr("_name") or "")
    end,
    ["symbol()"] = function()
        tos.result("string", tos.getStr("_symbol") or "")
    end,
    ["decimals()"] = function()
        tos.result("uint8", tos.get("_decimals") or 18)
    end,
    ["totalSupply()"] = function()
        tos.result("uint256", tos.get("_supply") or 0)
    end,
    ["balanceOf(address)"] = function(owner)
        tos.result("uint256", _bal(owner))
    end,
    ["allowance(address,address)"] = function(owner, spender)
        tos.result("uint256", _allow(owner, spender))
    end,
    ["transfer(address,uint256)"] = function(to, amount)
        _transfer(tos.caller, to, amount)
        tos.result("bool", 1)
    end,
    ["approve(address,uint256)"] = function(spender, amount)
        local owner = tos.caller
        require(tos.isAddress(spender),       "TOS20: invalid spender")
        require(spender ~= tos.ZERO_ADDRESS,  "TOS20: approve to zero address")
        tos.mapSet("_allow", owner, spender, amount)
        tos.emit("Approval",
            "address indexed", owner,
            "address indexed", spender,
            "uint256",         amount)
        tos.result("bool", 1)
    end,
    ["transferFrom(address,address,uint256)"] = function(from, to, amount)
        local spender = tos.caller
        local allowed = _allow(from, spender)
        require(allowed >= amount, "TOS20: insufficient allowance")
        tos.mapSet("_allow", from, spender, allowed - amount)
        _transfer(from, to, amount)
        tos.result("bool", 1)
    end,
    fallback = function()
        tos.revert("TOS20: unknown selector")
    end,
}

return M
`

// tos721LuaSrc is the TOS-721 non-fungible token standard — a pure-Lua ERC-721
// equivalent for unique, individually owned tokens.
//
// Usage inside a contract:
//
//	local T = tos.import("tos721")
//	T.init("MyNFT", "MNFT")
//	tos.dispatch(T.handlers)
//
// T.init(name, symbol)
//
//	Registers an oncreate hook that, on the contract's first call:
//	  - stores name and symbol
//	  - records tos.caller as the contract owner (who may mint tokens)
//
// T.handlers  — pass directly to tos.dispatch(); implements:
//
//	name()                                     → string
//	symbol()                                   → string
//	ownerOf(uint256)                           → address
//	balanceOf(address)                         → uint256
//	getApproved(uint256)                       → address
//	isApprovedForAll(address,address)          → bool
//	approve(address,uint256)                   → bool
//	setApprovalForAll(address,bool)
//	transferFrom(address,address,uint256)
//	mint(address,uint256)                      — contract owner only
//	burn(uint256)                              — token owner only
//	fallback                                   → revert "TOS721: unknown selector"
//
// Storage keys (all prefixed with "_" to avoid collision with user keys):
//
//	_name, _symbol   — tos.getStr / tos.setStr
//	_cowner          — tos.getStr / tos.setStr  (contract owner address)
//	_bal             — tos.mapGet/mapSet("_bal", address)       uint256 balance
//	_own             — tos.mapGetStr/mapSetStr("_own", tokenId) address owner
//	_appr            — tos.mapGetStr/mapSetStr("_appr", tokenId) address approval
//	_opAppr          — tos.mapGet/mapSet("_opAppr", owner, op)  uint256 bool
//
// tokenId values are converted to strings with tostring() for use as map keys
// (e.g. tokenId 1 → "1").  This supports sequential IDs up to the precision of
// the Lua number type; for random 256-bit IDs use a sequential counter instead.
const tos721LuaSrc = `
local M = {}

function M.init(name, symbol)
    tos.oncreate(function()
        tos.setStr("_name",   name)
        tos.setStr("_symbol", symbol)
        tos.setStr("_cowner", tos.caller)
    end)
end

local function _ownerOf(tid)
    return tos.mapGetStr("_own", tid)
end

local function _exists(tid)
    local o = _ownerOf(tid)
    return o ~= nil and o ~= tos.ZERO_ADDRESS
end

local function _balOf(addr)
    return tos.mapGet("_bal", addr) or 0
end

local function _getApproved(tid)
    return tos.mapGetStr("_appr", tid) or tos.ZERO_ADDRESS
end

local function _isApprAll(owner, operator)
    return (tos.mapGet("_opAppr", owner, operator) or 0) ~= 0
end

local function _isApprovedOrOwner(spender, tid)
    local owner = _ownerOf(tid)
    return spender == owner
        or _getApproved(tid) == spender
        or _isApprAll(owner, spender)
end

local function _transfer(from, to, tid)
    require(tos.isAddress(to),      "TOS721: invalid recipient")
    require(to ~= tos.ZERO_ADDRESS, "TOS721: transfer to zero address")
    require(_ownerOf(tid) == from,  "TOS721: transfer from wrong owner")
    tos.mapSetStr("_appr", tid, tos.ZERO_ADDRESS)
    tos.mapSet("_bal", from, _balOf(from) - 1)
    tos.mapSet("_bal", to,   _balOf(to)   + 1)
    tos.mapSetStr("_own", tid, to)
    tos.emit("Transfer",
        "address indexed", from,
        "address indexed", to,
        "uint256 indexed", tid)
end

M.handlers = {
    ["name()"] = function()
        tos.result("string", tos.getStr("_name") or "")
    end,
    ["symbol()"] = function()
        tos.result("string", tos.getStr("_symbol") or "")
    end,
    ["ownerOf(uint256)"] = function(tokenId)
        local tid = tostring(tokenId)
        require(_exists(tid), "TOS721: token does not exist")
        tos.result("address", _ownerOf(tid))
    end,
    ["balanceOf(address)"] = function(addr)
        require(addr ~= tos.ZERO_ADDRESS, "TOS721: balance of zero address")
        tos.result("uint256", _balOf(addr))
    end,
    ["getApproved(uint256)"] = function(tokenId)
        local tid = tostring(tokenId)
        require(_exists(tid), "TOS721: token does not exist")
        tos.result("address", _getApproved(tid))
    end,
    ["isApprovedForAll(address,address)"] = function(owner, operator)
        tos.result("bool", _isApprAll(owner, operator) and 1 or 0)
    end,
    ["approve(address,uint256)"] = function(spender, tokenId)
        local tid = tostring(tokenId)
        require(_exists(tid), "TOS721: token does not exist")
        local owner = _ownerOf(tid)
        require(tos.caller == owner or _isApprAll(owner, tos.caller),
            "TOS721: not authorized to approve")
        require(tos.isAddress(spender), "TOS721: invalid spender")
        tos.mapSetStr("_appr", tid, spender)
        tos.emit("Approval",
            "address indexed", owner,
            "address indexed", spender,
            "uint256 indexed", tid)
        tos.result("bool", 1)
    end,
    ["setApprovalForAll(address,bool)"] = function(operator, approved)
        require(tos.isAddress(operator), "TOS721: invalid operator")
        require(operator ~= tos.caller,  "TOS721: approve to caller")
        tos.mapSet("_opAppr", tos.caller, operator, approved and 1 or 0)
        tos.emit("ApprovalForAll",
            "address indexed", tos.caller,
            "address indexed", operator,
            "bool",            approved)
    end,
    ["transferFrom(address,address,uint256)"] = function(from, to, tokenId)
        local tid = tostring(tokenId)
        require(_isApprovedOrOwner(tos.caller, tid), "TOS721: not authorized")
        _transfer(from, to, tid)
    end,
    ["mint(address,uint256)"] = function(to, tokenId)
        local tid = tostring(tokenId)
        require(tos.caller == tos.getStr("_cowner"), "TOS721: not contract owner")
        require(tos.isAddress(to),      "TOS721: invalid recipient")
        require(to ~= tos.ZERO_ADDRESS, "TOS721: mint to zero address")
        require(not _exists(tid),       "TOS721: token already exists")
        tos.mapSet("_bal", to, _balOf(to) + 1)
        tos.mapSetStr("_own", tid, to)
        tos.emit("Transfer",
            "address indexed", tos.ZERO_ADDRESS,
            "address indexed", to,
            "uint256 indexed", tid)
    end,
    ["burn(uint256)"] = function(tokenId)
        local tid = tostring(tokenId)
        require(_exists(tid), "TOS721: token does not exist")
        local owner = _ownerOf(tid)
        require(tos.caller == owner, "TOS721: not token owner")
        tos.mapSetStr("_appr", tid, tos.ZERO_ADDRESS)
        tos.mapSet("_bal", owner, _balOf(owner) - 1)
        tos.mapSetStr("_own", tid, tos.ZERO_ADDRESS)
        tos.emit("Transfer",
            "address indexed", owner,
            "address indexed", tos.ZERO_ADDRESS,
            "uint256 indexed", tid)
    end,
    fallback = function()
        tos.revert("TOS721: unknown selector")
    end,
}

return M
`

// accessLuaSrc is the Role-Based Access Control (RBAC) stdlib.
//
// Usage inside a contract:
//
//	local AC = tos.import("access")
//	AC.init()            -- call at top-level; idempotent one-time initialisation
//	AC.requireRole("MINTER")  -- guard sensitive functions
//
// AC.init()
//
//	Must be called at the TOP LEVEL of the contract script (not inside a
//	function).  On the first ever call to the contract it records tos.caller
//	as the DEFAULT_ADMIN.  Subsequent calls are no-ops (O(1) SLOAD check).
//
// Role functions:
//
//	AC.hasRole(role, addr)       → bool
//	AC.requireRole(role)         — revert if tos.caller lacks role
//	AC.grantRole(role, addr)     — caller must hold DEFAULT_ADMIN
//	AC.revokeRole(role, addr)    — caller must hold DEFAULT_ADMIN
//	AC.renounceRole(role)        — caller surrenders their own role
//
// Events:
//
//	RoleGranted(string role, address account, address sender)
//	RoleRevoked(string role, address account, address sender)
//
// Storage keys (prefixed "__ac" to minimise collision risk):
//
//	__ac_init   — tos.get/set uint256 flag; 1 once initialised
//	_roles      — tos.mapGet/mapSet("_roles", addr, role) uint256 flag (1=granted)
const accessLuaSrc = `
local M = {}

local ADMIN_ROLE = "DEFAULT_ADMIN"
local INIT_KEY   = "__ac_init"

-- init() — idempotent one-shot initialiser.
-- On the first transaction ever received by the contract, records tos.caller
-- as the DEFAULT_ADMIN.  All subsequent calls return immediately.
function M.init()
    if tos.get(INIT_KEY) ~= nil then return end
    tos.set(INIT_KEY, 1)
    tos.mapSet("_roles", tos.caller, ADMIN_ROLE, 1)
    tos.emit("RoleGranted", "string", ADMIN_ROLE,
             "address", tos.caller, "address", tos.caller)
end

-- hasRole(role, addr) → bool
function M.hasRole(role, addr)
    return tos.mapGet("_roles", addr, role) == 1
end

-- requireRole(role) — revert if tos.caller does not hold role
function M.requireRole(role)
    if not M.hasRole(role, tos.caller) then
        tos.revert("access: missing role " .. role)
    end
end

-- grantRole(role, addr) — caller must hold DEFAULT_ADMIN
function M.grantRole(role, addr)
    M.requireRole(ADMIN_ROLE)
    tos.mapSet("_roles", addr, role, 1)
    tos.emit("RoleGranted", "string", role,
             "address", addr, "address", tos.caller)
end

-- revokeRole(role, addr) — caller must hold DEFAULT_ADMIN
function M.revokeRole(role, addr)
    M.requireRole(ADMIN_ROLE)
    tos.mapSet("_roles", addr, role, 0)
    tos.emit("RoleRevoked", "string", role,
             "address", addr, "address", tos.caller)
end

-- renounceRole(role) — caller surrenders their own role
function M.renounceRole(role)
    tos.mapSet("_roles", tos.caller, role, 0)
    tos.emit("RoleRevoked", "string", role,
             "address", tos.caller, "address", tos.caller)
end

return M
`

// timelockLuaSrc is the Timelock stdlib — a two-step, time-delayed execution
// pattern analogous to OpenZeppelin's TimelockController.
//
// Usage inside a contract:
//
//	local TL = tos.import("timelock")
//	TL.init(minDelay)          -- call at top-level; first caller becomes admin
//
// Workflow:
//
//  1. Admin calls TL.schedule(target, value, calldata, salt, delay)
//     → stores eta = block.timestamp + max(delay, minDelay); returns opId
//  2. Anyone calls TL.execute(target, value, calldata, salt)
//     → verifies eta ≤ block.timestamp, then tos.call(target, value, calldata)
//  3. Admin may call TL.cancel(target, value, calldata, salt) to discard.
//
// Helper queries:
//
//	TL.isReady(target, value, calldata, salt) → bool
//	TL.eta(target, value, calldata, salt)     → number | nil
//
// Storage keys (prefixed "__tl" to minimise collision risk):
//
//	__tl_init   — tos.get/set; one-shot init flag
//	__tl_delay  — tos.get/set; minimum delay in seconds
//	__tl_admin  — tos.getStr/setStr; admin address
//	_tl_ops     — tos.mapGet/mapSet("_tl_ops", opId); scheduled eta (0 = unset)
//
// Events:
//
//	TimelockInit(address admin, uint256 minDelay)
//	OperationScheduled(address target, uint256 eta)
//	OperationExecuted(address target)
//	OperationCancelled(address target)
const timelockLuaSrc = `
local M = {}

local INIT_KEY  = "__tl_init"
local DELAY_KEY = "__tl_delay"
local ADMIN_KEY = "__tl_admin"

-- opId: deterministic identifier for (target, value, calldata, salt).
-- Uses keccak256 of the colon-separated string representation so that each
-- distinct parameter tuple maps to a unique 32-byte key.
local function opId(target, value, calldata, salt)
    return tos.keccak256(
        tostring(target)   .. ":"
     .. tostring(value)    .. ":"
     .. tostring(calldata) .. ":"
     .. tostring(salt))
end

-- M.init(minDelay) — idempotent one-shot initialiser.
-- On the first transaction to the contract, records tos.caller as admin and
-- stores minDelay (in seconds).  All subsequent calls are no-ops.
function M.init(minDelay)
    if tos.get(INIT_KEY) ~= nil then return end
    tos.set(INIT_KEY, 1)
    tos.set(DELAY_KEY, minDelay or 0)
    tos.setStr(ADMIN_KEY, tos.caller)
    tos.emit("TimelockInit", "address", tos.caller, "uint256", minDelay or 0)
end

-- M.schedule(target, value, calldata, salt [, delay]) → opId
-- Admin-only.  Queues a call to "target" with the given parameters.
-- The effective delay is max(delay, minDelay).  Returns the operation ID.
function M.schedule(target, value, calldata, salt, delay)
    tos.require(tos.caller == tos.getStr(ADMIN_KEY), "timelock: not admin")
    local minDelay = tos.get(DELAY_KEY) or 0
    local d = math.max(delay or 0, minDelay)
    local eta = tos.block.timestamp + d
    local id = opId(target, value, calldata, salt)
    tos.require(tos.mapGet("_tl_ops", id) == nil, "timelock: already scheduled")
    tos.mapSet("_tl_ops", id, eta)
    tos.emit("OperationScheduled", "address", target, "uint256", eta)
    return id
end

-- M.execute(target, value, calldata, salt)
-- Anyone may call.  Verifies the operation was scheduled and the delay has
-- elapsed, then dispatches tos.call(target, value, calldata).
function M.execute(target, value, calldata, salt)
    local id = opId(target, value, calldata, salt)
    local eta = tos.mapGet("_tl_ops", id)
    tos.require(eta ~= nil, "timelock: not scheduled")
    tos.require(tos.block.timestamp >= eta, "timelock: not ready")
    tos.mapSet("_tl_ops", id, 0)   -- mark consumed
    local ok, _ = tos.call(target, value or 0, calldata or "0x")
    tos.require(ok, "timelock: execution failed")
    tos.emit("OperationExecuted", "address", target)
end

-- M.cancel(target, value, calldata, salt)
-- Admin-only.  Removes a pending operation so it can never be executed.
function M.cancel(target, value, calldata, salt)
    tos.require(tos.caller == tos.getStr(ADMIN_KEY), "timelock: not admin")
    local id = opId(target, value, calldata, salt)
    tos.require(tos.mapGet("_tl_ops", id) ~= nil, "timelock: not scheduled")
    tos.mapSet("_tl_ops", id, 0)
    tos.emit("OperationCancelled", "address", target)
end

-- M.isReady(target, value, calldata, salt) → bool
function M.isReady(target, value, calldata, salt)
    local id = opId(target, value, calldata, salt)
    local eta = tos.mapGet("_tl_ops", id)
    if eta == nil or eta == 0 then return false end
    return tos.block.timestamp >= eta
end

-- M.eta(target, value, calldata, salt) → number | nil
-- Returns the scheduled execution timestamp, or nil if not scheduled.
function M.eta(target, value, calldata, salt)
    local id = opId(target, value, calldata, salt)
    return tos.mapGet("_tl_ops", id)
end

return M
`
