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
	signature, err := genSignature(chainID, signer.PrivateKey, entryPointAddr, userOp)
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

// XSign signs the UserOperations with the given private key.
func XSign(chainIDs []*big.Int, entryPointAddr common.Address, signer *signer.EOA, userOps []*model.UserOperation) ([]*model.UserOperation, error) {
	signature, err := genXSignature(chainIDs, signer.PrivateKey, entryPointAddr, userOps)
	if err != nil {
		return nil, err
	}

	for _, op := range userOps {
		op.Signature = signature
	}

	// Use VerifyXSignature for cross-chain signatures
	if !VerifyXSignature(chainIDs, signer.PublicKey, entryPointAddr, userOps) {
		return nil, fmt.Errorf("signature is invalid")
	}

	return userOps, nil
}

// genSignature generates an ECDSA signature.
func genSignature(chainID *big.Int, privateKey *ecdsa.PrivateKey, entryPointAddr common.Address, userOp *model.UserOperation) ([]byte, error) {
	userOpHashObj := userOp.GetUserOpHash(entryPointAddr, chainID)

	prefixedHash := getEtherXMsgHash(userOpHashObj)

	signature, err := crypto.Sign(prefixedHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper

	return signature, nil
}

// genXSignature generates an ECDSA signature for multiple user operations.
func genXSignature(chainIDs []*big.Int, privateKey *ecdsa.PrivateKey, entryPointAddr common.Address, userOps []*model.UserOperation) ([]byte, error) {
	count := len(userOps)
	hashes := make([]common.Hash, count)
	hashBigs := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		hashes[i] = userOps[i].GetUserOpHash(entryPointAddr, chainIDs[i])
		hashBigs[i] = new(big.Int).SetBytes(hashes[i][:])
	}
	// Bubble sort the hashes; because the count is small (<4), this is efficient enough
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
		fmt.Printf("sorted hashes[%d]: 0x%x\n", i, hashes[i][:])
		concatenatedHashes = append(concatenatedHashes, hashes[i][:]...)
	}

	// Compute xChainHash
	xChainHash := crypto.Keccak256Hash(concatenatedHashes)
	fmt.Printf("xChainHash: 0x%x, length:%d, %s\n", xChainHash[:], len(xChainHash), xChainHash)

	prefixedHash := getEtherXMsgHash(xChainHash)
	fmt.Printf("toEthSignedMessageHash: 0x%x\n", prefixedHash[:])

	signature, err := crypto.Sign(prefixedHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	// Transform V from 0/1 to 27/28 according to the yellow paper
	if signature[64] == 0 || signature[64] == 1 {
		signature[64] += 27
	}

	fmt.Printf("signature: 0x%x\n", signature[:])

	return signature, nil
}

// getEtherXMsgHash computes Ethereum signed message hash with fixed prefix for
// a cross chain operations hash which
func getEtherXMsgHash(xChainHash common.Hash) common.Hash {
	const ethMsgPrefix = "\x19Ethereum Signed Message:\n32"
	prefix := []byte(ethMsgPrefix)
	message := append(prefix, xChainHash.Bytes()...)
	prefixedHash := crypto.Keccak256Hash(message)

	return prefixedHash
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
	fmt.Printf("verifying userOpHash: 0x%x\n", userOpHash)

	prefixedHash := getEtherXMsgHash(userOp.GetUserOpHash(entryPointAddr, chainID))
	fmt.Printf("verifying prefixedHash: 0x%x\n", prefixedHash)

	recoveredPubKey, err := crypto.SigToPub(prefixedHash.Bytes(), signature)
	if err != nil {
		fmt.Printf("Failed to recover public key: %v\n", err)
		return false
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	expectedAddress := crypto.PubkeyToAddress(*publicKey)

	return recoveredAddress == expectedAddress
}

func VerifyXSignature(chainIDs []*big.Int, publicKey *ecdsa.PublicKey, entryPointAddr common.Address, userOps []*model.UserOperation) bool {
	if len(userOps[0].Signature) != 65 {
		panic(errors.New("signature must be 65 bytes long"))
	}
	if userOps[0].Signature[64] != 27 && userOps[0].Signature[64] != 28 {
		panic(errors.New("invalid Ethereum signature (V is not 27 or 28)"))
	}

	signature := bytes.Clone(userOps[0].Signature) // Assuming all signatures are the same
	signature[64] -= 27                            // Transform yellow paper V from 27/28 to 0/1

	count := len(userOps)
	hashes := make([]common.Hash, count)
	hashBigs := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		hashes[i] = userOps[i].GetUserOpHash(entryPointAddr, chainIDs[i])
		hashBigs[i] = new(big.Int).SetBytes(hashes[i][:])
	}
	// Bubble sort the hashes
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

	xChainHash := crypto.Keccak256Hash(concatenatedHashes)
	prefixedHash := getEtherXMsgHash(xChainHash)

	recoveredPubKey, err := crypto.SigToPub(prefixedHash.Bytes(), signature)
	if err != nil {
		fmt.Printf("Failed to recover public key: %v\n", err)
		return false
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	expectedAddress := crypto.PubkeyToAddress(*publicKey)

	return recoveredAddress == expectedAddress
}
