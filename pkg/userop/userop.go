package userop

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

// Sign signs the UserOperation with the given private key.
func Sign(chainID *big.Int, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation) (*model.UserOperation, error) {
	signature, err := getSignature(chainID, signer.PrivateKey, entryPointAddr, userOp)
	if err != nil {
		return nil, err
	}
	// Verify the signature
	userOp.Signature = signature
	if !VerifySignature(chainID, signer.PublicKey, entryPointAddr, userOp) {
		return nil, fmt.Errorf("signature is invalid")
	}
	return userOp, nil
}

// getSignature gets the signature.
func getSignature(chainID *big.Int, privateKey *ecdsa.PrivateKey, entryPointAddr common.Address, userOp *model.UserOperation) ([]byte, error) {
	userOpHashObj := userOp.GetUserOpHash(entryPointAddr, chainID)

	userOpHash := userOpHashObj.Bytes()
	prefixedHash := crypto.Keccak256Hash(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(userOpHash), userOpHash)),
	)

	signature, err := crypto.Sign(prefixedHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	// Normalize S value for Ethereum
	// sValue := big.NewInt(0).SetBytes(signature[32:64])
	// secp256k1N := crypto.S256().Params().N
	// if sValue.Cmp(new(big.Int).Rsh(secp256k1N, 1)) > 0 {
	// 	sValue.Sub(secp256k1N, sValue)
	// 	copy(signature[32:64], sValue.Bytes())
	// }
	return signature, nil
}

// VerifySignature verifies the signature of the UserOperation.
func VerifySignature(chainID *big.Int, publicKey *ecdsa.PublicKey, entryPointAddr common.Address, userOp *model.UserOperation) bool {
	if len(userOp.Signature) != 65 {
		panic(errors.New("signature must be 65 bytes long"))
	}
	if userOp.Signature[64] != 27 && userOp.Signature[64] != 28 {
		panic(errors.New("invalid Ethereum signature (V is not 27 or 28)"))
	}

	signature := bytes.Clone(userOp.Signature) // Not in RSV format

	signature[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	userOpHash := userOp.GetUserOpHash(entryPointAddr, chainID).Bytes()

	prefixedHash := crypto.Keccak256Hash(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(userOpHash), userOpHash)),
	)

	recoveredPubKey, err := crypto.SigToPub(prefixedHash.Bytes(), signature)
	if err != nil {
		fmt.Printf("Failed to recover public key: %v\n", err)
		return false
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	expectedAddress := crypto.PubkeyToAddress(*publicKey)

	return recoveredAddress == expectedAddress
}
