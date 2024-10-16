package userop_test

import (
	"crypto/ecdsa"
	"encoding/hex"
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

func TestCrossChainECDSASignature_MultipleUserOps(t *testing.T) {
	account, entryPointAddr, chainIDs, userOps := setupMultipleUserOps(t)

	// Generate cross-chain signature
	signedUserOps, err := userop.XSign(chainIDs, entryPointAddr, account, userOps)
	require.NoError(t, err)

	// Verify the signature
	isValid := userop.VerifyXSignature(chainIDs, account.PublicKey, entryPointAddr, signedUserOps)
	require.True(t, isValid, "Signature is invalid for cross-chain UserOperations")

	// Check if the signature matches the one from the Solidity test
	expectedSignature := "babbe1fb0f5154d9fb263e64d1b0d9a74b184aaaaa8655a3a4fc8344bc4a8580691393eecc7cd518f0f95119c235b11c566941517aa8cc74ddf0add0af1131ae1b"
	actualSignature := fmt.Sprintf("%x", signedUserOps[0].Signature)
	require.Equal(t, expectedSignature, actualSignature, "Generated signature does not match expected signature")
}

func TestCrossChainECDSASignature_MultipleUserOpsWithHashes(t *testing.T) {
	account, entryPointAddr, chainIDs, userOps := setupMultipleUserOps(t)

	// Generate cross-chain signature
	hashes := []common.Hash{userOps[0].GetUserOpHash(entryPointAddr, chainIDs[0]), userOps[1].GetUserOpHash(entryPointAddr, chainIDs[1])}

	messageHash := userop.GenXHash(hashes)
	fmt.Printf("messageHash: %s\n", messageHash.String())

	signature, err := userop.GenerateSignature(messageHash, account.PrivateKey)
	require.NoError(t, err)

	isValid := userop.VerifyHashSignature(messageHash, signature, account.PublicKey)
	require.True(t, isValid, "Signature is invalid for cross-chain UserOperations")

	// Verify the signature
	expectedSignature := "babbe1fb0f5154d9fb263e64d1b0d9a74b184aaaaa8655a3a4fc8344bc4a8580691393eecc7cd518f0f95119c235b11c566941517aa8cc74ddf0add0af1131ae1b"
	actualSignature := fmt.Sprintf("%x", signature)
	require.Equal(t, expectedSignature, actualSignature, "Generated signature does not match expected signature")
}

func TestCrossChainECDSASignature_SingleUserOpWithHash(t *testing.T) {
	account, entryPointAddr, chainIDs, userOps := setupSingleUserOp(t)

	// Generate cross-chain signature
	hashes := []common.Hash{userOps[0].GetUserOpHash(entryPointAddr, chainIDs[0])}

	// Use destChainID and destUserOp for signing
	signedUserOp, err := userop.Sign(chainIDs[1], entryPointAddr, account, userOps[1], hashes)
	require.NoError(t, err)

	fmt.Printf("signature: %s\n", hex.EncodeToString(signedUserOp.Signature))

	messageHash := userop.GetXHash(userOps[1], hashes, entryPointAddr, []*big.Int{chainIDs[1]})
	fmt.Printf("messageHash: %s\n", messageHash.String())

	isValid := userop.VerifyHashSignature(messageHash, signedUserOp.Signature, account.PublicKey)
	require.True(t, isValid, "Signature is invalid for cross-chain UserOperations")

	// Verify the signature
	expectedSignature := "babbe1fb0f5154d9fb263e64d1b0d9a74b184aaaaa8655a3a4fc8344bc4a8580691393eecc7cd518f0f95119c235b11c566941517aa8cc74ddf0add0af1131ae1b"
	actualSignature := fmt.Sprintf("%x", signedUserOp.Signature)
	require.Equal(t, expectedSignature, actualSignature, "Generated signature does not match expected signature")
}

func setupMultipleUserOps(t *testing.T) (*signer.EOA, common.Address, []*big.Int, []*model.UserOperation) {
	account, entryPointAddr, sourceChainID, destChainID, sourceUserOp, destUserOp := createUserOps(t)
	chainIDs := []*big.Int{sourceChainID, destChainID}
	userOps := []*model.UserOperation{sourceUserOp, destUserOp}
	return account, entryPointAddr, chainIDs, userOps
}

func setupSingleUserOp(t *testing.T) (*signer.EOA, common.Address, []*big.Int, []*model.UserOperation) {
	account, entryPointAddr, sourceChainID, destChainID, sourceUserOp, destUserOp := createUserOps(t)
	chainIDs := []*big.Int{sourceChainID, destChainID}
	userOps := []*model.UserOperation{sourceUserOp, destUserOp}
	return account, entryPointAddr, chainIDs, userOps
}

func createUserOps(t *testing.T) (*signer.EOA, common.Address, *big.Int, *big.Int, *model.UserOperation, *model.UserOperation) {
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
	return signer, entryPointAddr, sourceChainID, destChainID, sourceUserOp, destUserOp
}
