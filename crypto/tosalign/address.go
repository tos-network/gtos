package tosalign

import (
	"errors"
	"fmt"
)

const (
	MainnetAddressPrefix = "tos"
	TestnetAddressPrefix = "tst"
)

type AddressType byte

const (
	AddressTypeNormal AddressType = 0
	AddressTypeData   AddressType = 1
)

type Address struct {
	mainnet bool
	kind    AddressType
	key     CompressedPublicKey
	data    []byte
}

var (
	errAddressInvalidPrefix  = errors.New("invalid address prefix")
	errAddressInvalidFormat  = errors.New("invalid address format")
	errAddressInvalidType    = errors.New("invalid address type")
	errAddressInvalidPayload = errors.New("invalid address payload")
)

func NewAddress(mainnet bool, key CompressedPublicKey) Address {
	return Address{
		mainnet: mainnet,
		kind:    AddressTypeNormal,
		key:     key,
	}
}

// NewDataAddress keeps raw serialized DataElement bytes to preserve round-trip compatibility.
func NewDataAddress(mainnet bool, key CompressedPublicKey, rawData []byte) Address {
	cp := make([]byte, len(rawData))
	copy(cp, rawData)
	return Address{
		mainnet: mainnet,
		kind:    AddressTypeData,
		key:     key,
		data:    cp,
	}
}

func (a Address) IsMainnet() bool {
	return a.mainnet
}

func (a Address) Type() AddressType {
	return a.kind
}

func (a Address) PublicKey() CompressedPublicKey {
	return a.key
}

func (a Address) RawData() []byte {
	cp := make([]byte, len(a.data))
	copy(cp, a.data)
	return cp
}

func (a Address) AsString() (string, error) {
	bits, err := ConvertBits(a.compress(), 8, 5, true)
	if err != nil {
		return "", err
	}

	hrp := TestnetAddressPrefix
	if a.mainnet {
		hrp = MainnetAddressPrefix
	}
	return Bech32Encode(hrp, bits)
}

func AddressFromString(address string) (Address, error) {
	hrp, data, err := Bech32Decode(address)
	if err != nil {
		return Address{}, err
	}
	if hrp != MainnetAddressPrefix && hrp != TestnetAddressPrefix {
		return Address{}, fmt.Errorf("%w: got %q, expected %q or %q", errAddressInvalidPrefix, hrp, MainnetAddressPrefix, TestnetAddressPrefix)
	}

	bytes, err := ConvertBits(data, 5, 8, false)
	if err != nil {
		return Address{}, err
	}

	addr, err := decompressAddress(bytes, hrp)
	if err != nil {
		return Address{}, err
	}

	expected := TestnetAddressPrefix
	if addr.mainnet {
		expected = MainnetAddressPrefix
	}
	if hrp != expected {
		return Address{}, fmt.Errorf("%w: got %q, expected %q", errAddressInvalidPrefix, hrp, expected)
	}
	return addr, nil
}

func (a Address) compress() []byte {
	out := make([]byte, 0, CompressedPublicKeySize+1+len(a.data))
	out = append(out, a.key[:]...)
	out = append(out, byte(a.kind))
	if a.kind == AddressTypeData {
		out = append(out, a.data...)
	}
	return out
}

func decompressAddress(raw []byte, hrp string) (Address, error) {
	if len(raw) < CompressedPublicKeySize+1 {
		return Address{}, errAddressInvalidPayload
	}
	mainnet := hrp == MainnetAddressPrefix

	key, err := CompressedPublicKeyFromBytes(raw[:CompressedPublicKeySize])
	if err != nil {
		return Address{}, err
	}

	typ := AddressType(raw[CompressedPublicKeySize])
	remain := raw[CompressedPublicKeySize+1:]

	switch typ {
	case AddressTypeNormal:
		if len(remain) != 0 {
			return Address{}, errAddressInvalidFormat
		}
		return NewAddress(mainnet, key), nil
	case AddressTypeData:
		return NewDataAddress(mainnet, key, remain), nil
	default:
		return Address{}, errAddressInvalidType
	}
}
