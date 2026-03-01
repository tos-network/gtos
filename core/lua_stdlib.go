package core

import lua "github.com/tos-network/glua"

// luaBuiltinModules maps module names to pre-compiled bytecode.
// Compiled once at package init from the Lua source constants below.
// Loaded via tos.import("moduleName") inside contract scripts.
var luaBuiltinModules map[string][]byte

func init() {
	luaBuiltinModules = make(map[string][]byte, 2)
	for name, src := range map[string]string{
		"tos20":  tos20LuaSrc,
		"tos721": tos721LuaSrc,
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
