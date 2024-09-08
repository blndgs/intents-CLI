package userop

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/blndgs/model"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

const (
	ConventionalUserOp byte = 0
	SourceChainUserOp  byte = 1
	DestChainUserOp    byte = 2

	KeyHex              = "e8776ff1bf88707b464bda52319a747a71c41a137277161dcabb9f821d6c0bd7"
	EntryPointAddress   = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
	RecipientAddress    = "0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518"
	SourceChainID       = 137
	DestChainID         = 56
	SourceTransferValue = 50000000000000000 // 0.05 MATIC
	DestTransferValue   = 50000000000000    // 0.00005 BNB
)

func TestCrossChainUserOperation(t *testing.T) {
	eoa, err := signer.New(KeyHex)
	assert.NoError(t, err)

	entryPointAddr := common.HexToAddress(EntryPointAddress)
	recipient := common.HexToAddress(RecipientAddress)

	var (
		SourceChainIDBig = big.NewInt(int64(uint16(SourceChainID)))
		DestChainIDBig   = big.NewInt(int64(uint16(DestChainID)))
	)

	// Create source UserOp (Polygon, chain ID 137)
	sourceUserOp := createTransferUserOp(eoa.Address, recipient, big.NewInt(SourceTransferValue), SourceChainUserOp)

	// Create destination UserOp (BSC, chain ID 56)
	destUserOp := createTransferUserOp(eoa.Address, recipient, big.NewInt(DestTransferValue), DestChainUserOp)

	// Sign the cross-chain UserOp
	srcUserOpSigned, destUserOpSigned, err := xSign(SourceChainIDBig, DestChainIDBig, entryPointAddr, eoa, sourceUserOp, destUserOp)
	assert.NoError(t, err)

	// Verify the signatures
	isValidSource := verifySourceUserOp(SourceChainIDBig, entryPointAddr, srcUserOpSigned, eoa.PublicKey)
	assert.True(t, isValidSource, "Source UserOp signature verification failed")

	isValidDest := verifyDestUserOp(DestChainIDBig, entryPointAddr, destUserOpSigned, eoa.PublicKey)
	assert.True(t, isValidDest, "Destination UserOp signature verification failed")

	// Test invalid signatures
	invalidSourceUserOp := *srcUserOpSigned
	invalidSourceUserOp.Signature[1] ^= 0x01 // Modify the second byte to avoid changing the opType
	invalidDestUserOp := *destUserOpSigned
	invalidDestUserOp.Signature[1] ^= 0x01 // Modify the second byte to avoid changing the opType

	isValidSource = verifySourceUserOp(SourceChainIDBig, entryPointAddr, &invalidSourceUserOp, eoa.PublicKey)
	assert.False(t, isValidSource, "Invalid Source UserOp signature verification should fail")

	isValidDest = verifyDestUserOp(DestChainIDBig, entryPointAddr, &invalidDestUserOp, eoa.PublicKey)
	assert.False(t, isValidDest, "Invalid Destination UserOp signature verification should fail")
}

func createTransferUserOp(from, to common.Address, amount *big.Int, opType byte) *model.UserOperation {
	transferData := crypto.Keccak256([]byte("transfer(address,uint256)"))[0:4]
	transferData = append(transferData, common.LeftPadBytes(to.Bytes(), 32)...)
	transferData = append(transferData, common.LeftPadBytes(amount.Bytes(), 32)...)

	return &model.UserOperation{
		Sender:               from,
		Nonce:                big.NewInt(0),
		InitCode:             []byte{},
		CallData:             transferData,
		CallGasLimit:         big.NewInt(100000),
		VerificationGasLimit: big.NewInt(100000),
		PreVerificationGas:   big.NewInt(21000),
		MaxFeePerGas:         big.NewInt(20000000000),
		MaxPriorityFeePerGas: big.NewInt(1000000000),
		PaymasterAndData:     []byte{},
		Signature:            []byte{opType}, // Add opType as the first byte of the signature
	}
}

func embedDestUserOp(sourceChainID uint16, sourceCallData []byte, destChainID uint16, destUserOp *model.UserOperation) []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, sourceChainID)

	srcCallDataLen := uint16(len(sourceCallData))
	srcCallDataLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(srcCallDataLenBytes, srcCallDataLen)
	result = append(result, srcCallDataLenBytes...)
	result = append(result, sourceCallData...)

	destChainIDBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(destChainIDBytes, destChainID)
	result = append(result, destChainIDBytes...)

	destUserOpEncoded := destUserOp.PackForSignature()
	destUserOpLength := uint16(len(destUserOpEncoded))
	destUserOpLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(destUserOpLengthBytes, destUserOpLength)
	result = append(result, destUserOpLengthBytes...)
	result = append(result, destUserOpEncoded...)

	fmt.Printf("embedDestUserOp result: %x\n", result)
	return result
}

func embedSourceHash1(destChainID uint16, destCallData []byte, sourceChainID uint16, hash1 common.Hash) []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, destChainID)

	destCallDataLen := uint16(len(destCallData))
	destCallDataLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(destCallDataLenBytes, destCallDataLen)
	result = append(result, destCallDataLenBytes...)
	result = append(result, destCallData...)

	sourceChainIDBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sourceChainIDBytes, sourceChainID)
	result = append(result, sourceChainIDBytes...)

	result = append(result, hash1.Bytes()...)

	return result
}

func xSign(sourceChainID, destChainID *big.Int, entryPointAddr common.Address, signer *signer.EOA, sourceUserOp, destUserOp *model.UserOperation) (*model.UserOperation, *model.UserOperation, error) {
	// Modify CallData for source UserOp
	sourceUserOp.CallData = embedDestUserOp(uint16(sourceChainID.Uint64()), sourceUserOp.CallData, uint16(destChainID.Uint64()), destUserOp)

	// Generate hash1
	hash1 := sourceUserOp.GetUserOpHash(entryPointAddr, sourceChainID)

	// Modify CallData for destination UserOp
	destUserOp.CallData = embedSourceHash1(uint16(destChainID.Uint64()), destUserOp.CallData, uint16(sourceChainID.Uint64()), hash1)

	// Generate hash2
	hash2 := getHash2(hash1, destUserOp, entryPointAddr, destChainID)
	fmt.Printf("xSign generated hash2: %x\n", hash2)

	signature, err := xGenSignature(signer.PrivateKey, hash2)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("xSign generated signature: %x\n", signature)

	sourceUserOp.Signature = append([]byte{SourceChainUserOp}, signature...)
	destUserOp.Signature = append([]byte{DestChainUserOp}, signature...)

	return sourceUserOp, destUserOp, nil
}

func xGenSignature(privateKey *ecdsa.PrivateKey, hash2 common.Hash) ([]byte, error) {
	prefixedHash := crypto.Keccak256Hash(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(hash2.Bytes()), hash2.Bytes())),
	)

	signature, err := crypto.Sign(prefixedHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	signature[64] += 27
	return signature, nil
}

func verifySourceUserOp(sourceChainID *big.Int, entryPointAddr common.Address, sourceUserOp *model.UserOperation, publicKey *ecdsa.PublicKey) bool {
	fmt.Printf("Verifying Source UserOp: %+v\n", sourceUserOp)

	if len(sourceUserOp.Signature) != 66 || sourceUserOp.Signature[0] != SourceChainUserOp {
		fmt.Println("Invalid signature length or opType")
		return false
	}

	signature := sourceUserOp.Signature[1:]

	// Generate hash1
	hash1 := sourceUserOp.GetUserOpHash(entryPointAddr, sourceChainID)
	fmt.Printf("Generated hash1: %x\n", hash1)

	// Extract destination UserOp from CallData
	destUserOp, destChainID, err := extractDestUserOp(sourceUserOp.CallData)
	if err != nil {
		fmt.Printf("Error extracting destination UserOp: %v\n", err)
		return false
	}
	fmt.Printf("Extracted destUserOp: %+v\n", destUserOp)
	fmt.Printf("Extracted destChainID: %d\n", destChainID)

	// Generate hash2
	hash2 := getHash2(hash1, destUserOp, entryPointAddr, destChainID)
	fmt.Printf("Generated hash2: %x\n", hash2)

	// Verify signature
	signatureNoRecovery := signature[:len(signature)-1] // Remove recovery id
	verified := crypto.VerifySignature(crypto.CompressPubkey(publicKey), hash2.Bytes(), signatureNoRecovery)

	if !verified {
		fmt.Println("Signature verification failed")
	}

	return verified
}

func verifyDestUserOp(destChainID *big.Int, entryPointAddr common.Address, destUserOp *model.UserOperation, publicKey *ecdsa.PublicKey) bool {
	if len(destUserOp.Signature) != 66 || destUserOp.Signature[0] != DestChainUserOp {
		return false
	}

	signature := bytes.Clone(destUserOp.Signature[1:])
	signature[64] -= 27

	// Extract hash1 and source chain ID from CallData
	hash1, sourceChainID, err := extractSourceHash1(destUserOp.CallData)
	if err != nil {
		return false
	}

	println("sourceChainID: ", sourceChainID.String())

	// Generate hash2
	hash2 := getHash2(hash1, destUserOp, entryPointAddr, destChainID)

	// Verify signature
	prefixedHash := crypto.Keccak256Hash(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(hash2.Bytes()), hash2.Bytes())),
	)

	recoveredPubKey, err := crypto.SigToPub(prefixedHash.Bytes(), signature)
	if err != nil {
		return false
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	expectedAddress := crypto.PubkeyToAddress(*publicKey)

	return recoveredAddress == expectedAddress
}

func extractDestUserOp(callData []byte) (*model.UserOperation, *big.Int, error) {
	fmt.Printf("extractDestUserOp input: %x\n", callData)

	if len(callData) < 8 {
		return nil, nil, fmt.Errorf("invalid callData length")
	}

	sourceChainID := binary.BigEndian.Uint16(callData[:2])
	fmt.Printf("sourceChainID: %d\n", sourceChainID)

	srcCallDataLen := binary.BigEndian.Uint16(callData[2:4])
	fmt.Printf("srcCallDataLen: %d\n", srcCallDataLen)

	destChainIDStart := 4 + srcCallDataLen
	fmt.Printf("destChainIDStart: %d\n", destChainIDStart)

	if len(callData) < int(destChainIDStart+4) {
		return nil, nil, fmt.Errorf("invalid callData length for destChainID")
	}

	destChainID := binary.BigEndian.Uint16(callData[destChainIDStart : destChainIDStart+2])
	fmt.Printf("destChainID: %d\n", destChainID)

	destUserOpLen := binary.BigEndian.Uint16(callData[destChainIDStart+2 : destChainIDStart+4])
	fmt.Printf("destUserOpLen: %d\n", destUserOpLen)

	destUserOpStart := destChainIDStart + 4
	fmt.Printf("destUserOpStart: %d\n", destUserOpStart)

	if len(callData) < int(destUserOpStart+destUserOpLen) {
		return nil, nil, fmt.Errorf("invalid callData length for destUserOp")
	}

	destUserOpBytes := callData[destUserOpStart : destUserOpStart+destUserOpLen]
	fmt.Printf("destUserOpBytes: %x\n", destUserOpBytes)

	destUserOp := &model.UserOperation{}
	err := Unpack(destUserOp, destUserOpBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error unpacking destUserOp: %v", err)
	}

	return destUserOp, big.NewInt(int64(destChainID)), nil
}

func Unpack(op *model.UserOperation, data []byte) error {
	if len(data) < 320 {
		return fmt.Errorf("insufficient data length: got %d, want at least 320", len(data))
	}

	op.Sender = common.BytesToAddress(data[12:32])
	op.Nonce = new(big.Int).SetBytes(data[32:64])
	op.CallGasLimit = new(big.Int).SetBytes(data[128:160])
	op.VerificationGasLimit = new(big.Int).SetBytes(data[160:192])
	op.PreVerificationGas = new(big.Int).SetBytes(data[192:224])
	op.MaxFeePerGas = new(big.Int).SetBytes(data[224:256])
	op.MaxPriorityFeePerGas = new(big.Int).SetBytes(data[256:288])

	// Handle dynamic fields
	initCodeOffset := new(big.Int).SetBytes(data[64:96]).Uint64()
	callDataOffset := new(big.Int).SetBytes(data[96:128]).Uint64()
	paymasterAndDataOffset := new(big.Int).SetBytes(data[288:320]).Uint64()

	if initCodeOffset < uint64(len(data)) {
		initCodeLength := new(big.Int).SetBytes(data[initCodeOffset : initCodeOffset+32]).Uint64()
		if initCodeOffset+32+initCodeLength <= uint64(len(data)) {
			op.InitCode = data[initCodeOffset+32 : initCodeOffset+32+initCodeLength]
		}
	}

	if callDataOffset < uint64(len(data)) {
		callDataLength := new(big.Int).SetBytes(data[callDataOffset : callDataOffset+32]).Uint64()
		if callDataOffset+32+callDataLength <= uint64(len(data)) {
			op.CallData = data[callDataOffset+32 : callDataOffset+32+callDataLength]
		}
	}

	if paymasterAndDataOffset < uint64(len(data)) {
		paymasterAndDataLength := new(big.Int).SetBytes(data[paymasterAndDataOffset : paymasterAndDataOffset+32]).Uint64()
		if paymasterAndDataOffset+32+paymasterAndDataLength <= uint64(len(data)) {
			op.PaymasterAndData = data[paymasterAndDataOffset+32 : paymasterAndDataOffset+32+paymasterAndDataLength]
		}
	}

	return nil
}

func extractSourceHash1(callData []byte) (common.Hash, *big.Int, error) {
	if len(callData) < 38 {
		return common.Hash{}, nil, fmt.Errorf("invalid callData length")
	}

	destChainID := binary.BigEndian.Uint16(callData[:2])
	println("destChainID: ", destChainID)
	destCallDataLen := binary.BigEndian.Uint16(callData[2:4])
	sourceChainIDStart := 4 + destCallDataLen

	if len(callData) < int(sourceChainIDStart+34) {
		return common.Hash{}, nil, fmt.Errorf("invalid callData length")
	}

	sourceChainID := binary.BigEndian.Uint16(callData[sourceChainIDStart : sourceChainIDStart+2])
	hash1Start := sourceChainIDStart + 2

	hash1 := common.BytesToHash(callData[hash1Start : hash1Start+32])

	return hash1, big.NewInt(int64(sourceChainID)), nil
}

func getHash2(hash1 common.Hash, destUserOp *model.UserOperation, entryPoint common.Address, chainID *big.Int) common.Hash {
	var packed []byte
	packed = append(packed, hash1.Bytes()...)
	packed = append(packed, destUserOp.PackForSignature()...)
	packed = append(packed, common.LeftPadBytes(entryPoint.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(chainID.Bytes(), 32)...)

	return crypto.Keccak256Hash(packed)
}

func packForSignature(op *model.UserOperation) []byte {
	var packed []byte
	packed = append(packed, common.LeftPadBytes(op.Sender.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(op.Nonce.Bytes(), 32)...)
	packed = append(packed, crypto.Keccak256(op.InitCode)...)
	packed = append(packed, crypto.Keccak256(op.CallData)...)
	packed = append(packed, common.LeftPadBytes(op.CallGasLimit.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(op.VerificationGasLimit.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(op.PreVerificationGas.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(op.MaxFeePerGas.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(op.MaxPriorityFeePerGas.Bytes(), 32)...)
	packed = append(packed, crypto.Keccak256(op.PaymasterAndData)...)
	return crypto.Keccak256(packed)
}
