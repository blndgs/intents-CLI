package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
)

// AddCommonFlags adds common flags to the provided Cobra command.
// It adds a string flag 'userop' for user operation JSON and
func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("u", "", "User operation JSON")

	// Mark the 'userop' flag as required
	if err := cmd.MarkFlagRequired("u"); err != nil {
		panic(err)
	}
}

// GetUserOps parses the 'userop' JSON string or file provided in the command flags
// and returns a UserOperation object. It panics if the JSON string is empty,
// the file can't be read, or the JSON can't be parsed.
func GetUserOps(cmd *cobra.Command) *model.UserOperation {
	userOpInput, _ := cmd.Flags().GetString("u")

	var userOpJSON string
	if userOpInput == "" {
		panic("user operation JSON is required")
	}

	// Check if the input is JSON string or file path
	if userOpInput[0] == '{' {
		// Input is JSON string
		userOpJSON = userOpInput
	} else if fileExists(userOpInput) {
		// Input is a file path
		fileContent, err := os.ReadFile(userOpInput)
		if err != nil {
			panic(fmt.Errorf("error reading user operation file: %v", err))
		}
		userOpJSON = string(fileContent)
	} else {
		panic("invalid user operation input")
	}

	var userOp model.UserOperation
	err := json.Unmarshal([]byte(userOpJSON), &userOp)
	if err != nil {
		panic(fmt.Errorf("error parsing user operation JSON: %v", err))
	}
	return &userOp
}

// UpdateUserOp updates the given user operation based on the provided nonce flag.
// The function returns the updated UserOperation object.
func UpdateUserOp(userOp *model.UserOperation, nonce *big.Int) *model.UserOperation {
	zero := big.NewInt(0)

	// set sane default values
	if userOp.CallGasLimit.Cmp(zero) == 0 {
		userOp.CallGasLimit = big.NewInt(500000)
	}
	if userOp.VerificationGasLimit.Cmp(zero) == 0 {
		userOp.VerificationGasLimit = big.NewInt(65536)
	}
	if userOp.PreVerificationGas.Cmp(zero) == 0 {
		userOp.PreVerificationGas = big.NewInt(65536)
	}

	userOp.Nonce = nonce
	return userOp
}

// fileExists checks if a file exists at the given path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// PrintSignature prints the signature + hex encoded intent JSON (calldata).
func PrintSignature(userOp *model.UserOperation) {
	fmt.Printf("\nSignature value after solution:\n%s\n",
		hexutil.Encode(userOp.Signature)+hex.EncodeToString(userOp.CallData))
}
