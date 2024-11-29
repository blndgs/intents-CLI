package cmd

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/pkg/errors"
)

// EntryPointError represents a decoded error from the EntryPoint contract
type EntryPointError struct {
	ErrorType string
	OpIndex   uint64
	Reason    string
	ErrorData []byte
}

const EntryPointErrorABI = `[{
    "inputs": [
        {"type": "uint256", "name": "opIndex"},
        {"type": "string", "name": "reason"}
    ],
    "name": "FailedOp",
    "type": "function"
}, {
    "inputs": [
        {"type": "uint256", "name": "opIndex"},
        {"type": "string", "name": "reason"},
        {"type": "bytes", "name": "errorData"}
    ],
    "name": "UserOperationRevertReason",
    "type": "function"
}, {
    "inputs": [
        {"type": "address", "name": "sender"}
    ],
    "name": "SenderAddressResult",
    "type": "function"
}, {
    "inputs": [
        {"type": "address", "name": "aggregator"}
    ],
    "name": "SignatureValidationFailed",
    "type": "function"
}]`

// Error implements the error interface
func (e *EntryPointError) Error() string {
	if len(e.ErrorData) > 0 {
		return fmt.Sprintf("%s: opIndex=%d, reason=%s, errorData=0x%x",
			e.ErrorType, e.OpIndex, e.Reason, e.ErrorData)
	}
	return fmt.Sprintf("%s: opIndex=%d, reason=%s",
		e.ErrorType, e.OpIndex, e.Reason)
}

// Known EntryPoint error selectors
const (
	FailedOpSelector                = "220266b6"
	UserOperationRevertSelector     = "220266b7"
	SenderAddressResultSelector     = "63c9b437"
	SignatureValidationFailSelector = "08c379a0"
)

func DecodeEntryPointError(data []byte) (*EntryPointError, error) {
	if len(data) < 4 {
		return nil, errors.New("error data too short")
	}
	selector := hex.EncodeToString(data[:4])
	entryPointErr := &EntryPointError{}

	// Create necessary types
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create uint256 type")
	}
	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create string type")
	}
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create bytes type")
	}

	switch selector {
	case FailedOpSelector:
		entryPointErr.ErrorType = "FailedOp"
		arguments := abi.Arguments{
			{Name: "opIndex", Type: uint256Type},
			{Name: "reason", Type: stringType},
		}
		values, err := arguments.Unpack(data[4:])
		if err != nil {
			return nil, errors.Wrap(err, "failed to unpack FailedOp error")
		}
		opIndex := values[0].(*big.Int)
		entryPointErr.OpIndex = opIndex.Uint64()
		entryPointErr.Reason = values[1].(string)
	case UserOperationRevertSelector:
		entryPointErr.ErrorType = "UserOperationRevertReason"
		arguments := abi.Arguments{
			{Name: "opIndex", Type: uint256Type},
			{Name: "reason", Type: stringType},
			{Name: "errorData", Type: bytesType},
		}
		values, err := arguments.Unpack(data[4:])
		if err != nil {
			return nil, errors.Wrap(err, "failed to unpack UserOperationRevertReason error")
		}
		opIndex := values[0].(*big.Int)
		entryPointErr.OpIndex = opIndex.Uint64()
		entryPointErr.Reason = values[1].(string)
		entryPointErr.ErrorData = values[2].([]byte)
	// Handle other selectors as needed
	default:
		return nil, fmt.Errorf("unknown error selector: %s", selector)
	}
	return entryPointErr, nil
}
