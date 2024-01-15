package utils

import (
	"encoding/json"
	"log"
	"math/big"

	"github.com/blndgs/model"
	"github.com/spf13/cobra"
)

// AddCommonFlags adds common flags to the provided Cobra command.
// It adds a string flag 'userop' for user operation JSON and
// a boolean flag 'zerogas' to enable zero gas mode.
func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("userop", "", "User operation JSON")
	cmd.Flags().Bool("zerogas", false, "Use zero gas mode")

	// Mark the 'userop' flag as required
	if err := cmd.MarkFlagRequired("userop"); err != nil {
		panic(err)
	}
}

// IsZeroGas checks if the 'zerogas' flag is set in the command.
// It returns true if the 'zerogas' flag is set, otherwise false.
func IsZeroGas(cmd *cobra.Command) bool {
	zeroGas, _ := cmd.Flags().GetBool("zerogas")
	return zeroGas
}

// GetUserOps parses the 'userop' JSON string from the command flags
// and returns a UserOperation object. It logs a fatal error
// if the JSON string is empty or cannot be parsed.
func GetUserOps(cmd *cobra.Command) *model.UserOperation {
	userOpJSON, _ := cmd.Flags().GetString("userop")
	if userOpJSON == "" {
		log.Fatalf("User operation JSON is required")
	}

	var userOp model.UserOperation
	err := json.Unmarshal([]byte(userOpJSON), &userOp)
	if err != nil {
		log.Fatalf("Error parsing user operation JSON: %v", err)
	}
	return &userOp
}

// UpdateUserOp updates the given user operation based on the provided nonce and zeroGas flag.
// If zeroGas is true, all gas-related fields in the user operation are set to zero.
// The function returns the updated UserOperation object.
func UpdateUserOp(userOp *model.UserOperation, nonce *big.Int, zeroGas bool) *model.UserOperation {
	if zeroGas {
		userOp.CallGasLimit = big.NewInt(0)
		userOp.VerificationGasLimit = big.NewInt(0)
		userOp.PreVerificationGas = big.NewInt(0)
		userOp.MaxFeePerGas = big.NewInt(0)
		userOp.MaxPriorityFeePerGas = big.NewInt(0)
	}
	userOp.Nonce = nonce
	return userOp
}
