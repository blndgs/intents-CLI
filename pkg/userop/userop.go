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

// Sign signs a single UserOperation with the given private key.
func Sign(chainID *big.Int, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation) (*model.UserOperation, error) {
	userOps := []*model.UserOperation{userOp}
	chainIDs := []*big.Int{chainID}

	signedOps, err := signUserOperations(chainIDs, entryPointAddr, signer, userOps)
	if err != nil {
		return nil, err
	}
	return signedOps[0], nil
}

// XSign signs multiple UserOperations (cross-chain) with the given private key.
func XSign(chainIDs []*big.Int, entryPointAddr common.Address, signer *signer.EOA, userOps []*model.UserOperation) ([]*model.UserOperation, error) {
	if len(chainIDs) < 2 {
		return nil, errors.New("at least two chainIDs are required")
	}
	if len(userOps) < 2 {
		return nil, errors.New("at least two UserOperations are required")
	}
	return signUserOperations(chainIDs, entryPointAddr, signer, userOps)
}

// signUserOperations is a helper function to sign one or multiple UserOperations.
func signUserOperations(chainIDs []*big.Int, entryPointAddr common.Address, signer *signer.EOA, userOps []*model.UserOperation) ([]*model.UserOperation, error) {
	if len(chainIDs) != len(userOps) {
		return nil, errors.New("number of chainIDs and userOps must match")
	}

	messageHash := GetHash(userOps, entryPointAddr, chainIDs)
	signature, err := generateSignature(messageHash, signer.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Assign the signature to all UserOperations
	for _, op := range userOps {
		op.Signature = signature
	}

	// Verify the signature
	if !verifySignature(messageHash, signature, signer.PublicKey) {
		return nil, fmt.Errorf("signature is invalid")
	}

	return userOps, nil
}

// GetHash computes the hash to be signed for single or multiple UserOperations.
func GetHash(userOps []*model.UserOperation, entryPointAddr common.Address, chainIDs []*big.Int) common.Hash {
	count := len(userOps)
	hashes := make([]common.Hash, count)
	hashBigs := make([]*big.Int, count)

	for i := 0; i < count; i++ {
		hash := userOps[i].GetUserOpHash(entryPointAddr, chainIDs[i])
		hashes[i] = hash
		hashBigs[i] = new(big.Int).SetBytes(hash[:])
	}

	if count > 1 {
		// Sort the hashes
		for i := 0; i < count; i++ {
			for j := i + 1; j < count; j++ {
				if hashBigs[i].Cmp(hashBigs[j]) > 0 {
					hashBigs[i], hashBigs[j] = hashBigs[j], hashBigs[i]
					hashes[i], hashes[j] = hashes[j], hashes[i]
				}
			}
		}
		// Concatenate the sorted hashes
		var concatenatedHashes []byte
		for i := 0; i < count; i++ {
			concatenatedHashes = append(concatenatedHashes, hashes[i][:]...)
		}
		// Compute xChainHash
		xChainHash := crypto.Keccak256Hash(concatenatedHashes)
		return xChainHash
	}

	// Single UserOperation
	return hashes[0]
}

// generateSignature signs the prefixed message hash with the private key.
func generateSignature(messageHash common.Hash, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	prefixedHash := getEtherMsgHash(messageHash)

	signature, err := crypto.Sign(prefixedHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	// Transform V from 0/1 to 27/28 according to the yellow paper
	if signature[64] == 0 || signature[64] == 1 {
		signature[64] += 27
	}

	return signature, nil
}

// getEtherMsgHash computes Ethereum signed message hash with fixed prefix.
func getEtherMsgHash(messageHash common.Hash) common.Hash {
	const ethMsgPrefix = "\x19Ethereum Signed Message:\n32"
	prefix := []byte(ethMsgPrefix)
	message := append(prefix, messageHash.Bytes()...)
	return crypto.Keccak256Hash(message)
}

// VerifySignature verifies the signature of a single UserOperation.
func VerifySignature(chainID *big.Int, publicKey *ecdsa.PublicKey, entryPointAddr common.Address, userOp *model.UserOperation) bool {
	return VerifyXSignature([]*big.Int{chainID}, publicKey, entryPointAddr, []*model.UserOperation{userOp})
}

// VerifyXSignature verifies the signature of one or multiple UserOperations.
func VerifyXSignature(chainIDs []*big.Int, publicKey *ecdsa.PublicKey, entryPointAddr common.Address, userOps []*model.UserOperation) bool {
	if len(userOps) == 0 {
		return false
	}

	signature := userOps[0].Signature
	if len(signature) != 65 {
		panic(errors.New("signature must be 65 bytes long"))
	}
	if signature[64] != 27 && signature[64] != 28 {
		panic(errors.New("invalid Ethereum signature (V is not 27 or 28)"))
	}

	messageHash := GetHash(userOps, entryPointAddr, chainIDs)

	return verifySignature(messageHash, signature, publicKey)
}

// verifySignature verifies the signature against the message hash and public key.
func verifySignature(messageHash common.Hash, signature []byte, publicKey *ecdsa.PublicKey) bool {
	sigCopy := bytes.Clone(signature)
	sigCopy[64] -= 27 // Transform V from 27/28 (yellow paper) to 0/1

	prefixedHash := getEtherMsgHash(messageHash)

	recoveredPubKey, err := crypto.SigToPub(prefixedHash.Bytes(), sigCopy)
	if err != nil {
		fmt.Printf("Failed to recover public key: %v\n", err)
		return false
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	expectedAddress := crypto.PubkeyToAddress(*publicKey)

	return recoveredAddress == expectedAddress
}
