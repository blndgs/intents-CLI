package userop_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	"github.com/stretchr/testify/require"

	"github.com/blndgs/intents-sdk/pkg/userop"
)

func TestCrossChainECDSASignature(t *testing.T) {
	// Setup
	privateKey, err := crypto.HexToECDSA("e8776ff1bf88707b464bda52319a747a71c41a137277161dcabb9f821d6c0bd7")
	require.NoError(t, err)

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	signer := &signer.EOA{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	entryPointAddr := common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
	sourceChainID := big.NewInt(137) // Polygon
	destChainID := big.NewInt(56)    // BSC

	// Create UserOperations
	createUserOp := func(intent string) *model.UserOperation {
		return &model.UserOperation{
			Sender:               common.HexToAddress("0xc47331bcCdB9b68C54ABe2783064a91FeA22271b"),
			Nonce:                big.NewInt(0),
			InitCode:             []byte{},
			CallData:             []byte(intent),
			CallGasLimit:         big.NewInt(100000),
			VerificationGasLimit: big.NewInt(100000),
			PreVerificationGas:   big.NewInt(21000),
			MaxFeePerGas:         big.NewInt(20000000000), // 20 gwei
			MaxPriorityFeePerGas: big.NewInt(1000000000),  // 1 gwei
			PaymasterAndData:     []byte{},
			Signature:            []byte{},
		}
	}

	srcIntent := `{"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","amount":{"value":"DeC2s6dkAAA="},"chainId":{"value":"AAAAAAAAAIk="}},"toAsset":{"address":"0xc2132D05D31c914a87C6611C10748AEb04B58e8F","amount":{"value":"DeC2s6dkAAA="},"chainId":{"value":"AAAAAAAAADg="}}}`
	destIntent := srcIntent // Same intent for both chains in this example

	sourceUserOp := createUserOp(srcIntent)
	destUserOp := createUserOp(destIntent)

	// Generate cross-chain signature
	chainIDs := []*big.Int{sourceChainID, destChainID}
	userOps := []*model.UserOperation{sourceUserOp, destUserOp}

	signedUserOps, err := userop.XSign(chainIDs, entryPointAddr, signer, userOps)
	require.NoError(t, err)

	// Verify the signature
	isValid := userop.VerifyXSignature(chainIDs, signer.PublicKey, entryPointAddr, signedUserOps)
	require.True(t, isValid, "Signature is invalid for cross-chain UserOperations")

	// Check if the signature matches the one from the Solidity test
	expectedSignature := "21eea4f85e597719d9aaf71aa97048a9b5943f4b43d8b1d505c67f8b01b1acba5567323c8baeb1667e90ba1643b84a494f86d17ea801c8adc14a90871199b2d51c"
	actualSignature := fmt.Sprintf("%x", signedUserOps[0].Signature)
	require.Equal(t, expectedSignature, actualSignature, "Generated signature does not match expected signature")
}
