package abi

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ABI definition for handleOps function
const handleOpABI = `[
  {
    "inputs": [
      {
        "components": [
          {
            "internalType": "address",
            "name": "sender",
            "type": "address"
          },
          {
            "internalType": "uint256",
            "name": "nonce",
            "type": "uint256"
          },
          {
            "internalType": "bytes",
            "name": "initCode",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "callData",
            "type": "bytes"
          },
          {
            "internalType": "uint256",
            "name": "callGasLimit",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "verificationGasLimit",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "preVerificationGas",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "maxFeePerGas",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "maxPriorityFeePerGas",
            "type": "uint256"
          },
          {
            "internalType": "bytes",
            "name": "paymasterAndData",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "signature",
            "type": "bytes"
          }
        ],
        "internalType": "struct UserOperation[]",
        "name": "ops",
        "type": "tuple[]"
      },
      {
        "internalType": "address payable",
        "name": "beneficiary",
        "type": "address"
      }
    ],
    "name": "handleOps",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]`

func PrepareHandleOpCalldata(ops []model.UserOperation, beneficiary common.Address) (string, error) {
	parsedABI, err := abi.JSON(strings.NewReader(handleOpABI))
	if err != nil {
		return "", fmt.Errorf("failed to read abi json: %s", err)
	}

	// Convert UserOperation slice to []UserOperationABI for ABI encoding
	opsABI := make([]model.UserOperation, len(ops))
	for i, op := range ops {
		opsABI[i] = model.UserOperation{
			Sender:               op.Sender,
			Nonce:                op.Nonce,
			InitCode:             op.InitCode,
			CallData:             op.CallData,
			CallGasLimit:         op.CallGasLimit,
			VerificationGasLimit: op.VerificationGasLimit,
			PreVerificationGas:   op.PreVerificationGas,
			MaxFeePerGas:         op.MaxFeePerGas,
			MaxPriorityFeePerGas: op.MaxPriorityFeePerGas,
			PaymasterAndData:     op.PaymasterAndData,
			Signature:            op.Signature,
		}
	}

	calldata, err := parsedABI.Pack("handleOps", opsABI, beneficiary)
	if err != nil {
		return "", fmt.Errorf("failed to pack data: %s", err)
	}

	return "0x" + hex.EncodeToString(calldata), nil
}
