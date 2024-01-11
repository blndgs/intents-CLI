package cmd

import (
	"math/big"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
)

func getMockUserOp(sender common.Address, nonce *big.Int, zeroGas bool) *model.UserOperation {
	intentJSON := `{"sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}`
	println("intentJSON:", intentJSON)
	// Conditional gas values based on zeroGas flag
	var callGasLimit, verificationGasLimit, preVerificationGas, maxFeePerGas, maxPriorityFeePerGas *big.Int
	if zeroGas {
		callGasLimit = big.NewInt(0)
		verificationGasLimit = big.NewInt(0)
		preVerificationGas = big.NewInt(0)
		maxFeePerGas = big.NewInt(0)
		maxPriorityFeePerGas = big.NewInt(0)
	} else {
		callGasLimit = big.NewInt(0x2f44) // error if below 12100
		verificationGasLimit = big.NewInt(0xe4e0)
		preVerificationGas = big.NewInt(0xbb7c)
		maxFeePerGas = big.NewInt(0x12183576da)
		maxPriorityFeePerGas = big.NewInt(0x12183576ba)
	}

	return &model.UserOperation{
		Sender:               sender,
		Nonce:                nonce,
		InitCode:             []byte{},
		CallData:             []byte(intentJSON),
		CallGasLimit:         callGasLimit,
		VerificationGasLimit: verificationGasLimit,
		PreVerificationGas:   preVerificationGas,
		MaxFeePerGas:         maxFeePerGas,
		MaxPriorityFeePerGas: maxPriorityFeePerGas,
		PaymasterAndData:     []byte{},
	}
}
