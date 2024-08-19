package integration

import (
	"github.com/blndgs/intents-sdk/cmd"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"testing"
)

const (
	SenderAddress = "0xc291efdc1a6420cbb226294806604833982ed24d"
)

func TestSubmitOnChainUserOp(t *testing.T) {
	// Skip integration test when running go test ./...
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	testUserOp := &model.UserOperation{
		Sender:               common.HexToAddress(SenderAddress), // must match the .env EOA address
		CallGasLimit:         new(big.Int),
		PreVerificationGas:   new(big.Int),
		VerificationGasLimit: new(big.Int),
		InitCode:             []byte{},
		CallData:             []byte{},
		MaxFeePerGas:         new(big.Int),
		MaxPriorityFeePerGas: new(big.Int),
		PaymasterAndData:     []byte{},
	}
	cmd.SubmitOnChain(testUserOp)
}
