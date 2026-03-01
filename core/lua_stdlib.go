package core

import lua "github.com/tos-network/glua"

// luaBuiltinModules maps module names to pre-compiled bytecode.
// Compiled once at package init from the Lua source constants below.
// Loaded via tos.import("moduleName") inside contract scripts.
var luaBuiltinModules map[string][]byte

func init() {
	luaBuiltinModules = make(map[string][]byte, 1)
	for name, src := range map[string]string{
		"tos20": tos20LuaSrc,
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
