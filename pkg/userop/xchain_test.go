package userop_test

import (
	"crypto/ecdsa"
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

	srcIntent := `{"chainId":137, "sender":"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96","kind":"swap","hash":"","sellToken":"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE","buyToken":"0xc2132D05D31c914a87C6611C10748AEb04B58e8F","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}`
	destIntent := srcIntent // Same intent for both chains in this example

	sourceUserOp := createUserOp(srcIntent)
	destUserOp := createUserOp(destIntent)

	// Generate cross-chain signature
	signedUserOps, err := userop.XSign([]*big.Int{sourceChainID, destChainID}, entryPointAddr, signer, []*model.UserOperation{sourceUserOp, destUserOp})
	require.NoError(t, err)

	// Check if the signature matches the one from the Solidity test
	expectedSignature := "babbe1fb0f5154d9fb263e64d1b0d9a74b184aaaaa8655a3a4fc8344bc4a8580691393eecc7cd518f0f95119c235b11c566941517aa8cc74ddf0add0af1131ae1b"
	require.Equal(t, expectedSignature, common.Bytes2Hex(signedUserOps[0].Signature), "Generated signature does not match expected signature")

	// Verify signatures
	userop.VerifyXSignature([]*big.Int{sourceChainID, destChainID}, signer.PublicKey, entryPointAddr, signedUserOps)
}
