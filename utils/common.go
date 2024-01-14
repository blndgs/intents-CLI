package utils

import (
	"encoding/json"
	"log"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

func ReadFlags(cmd *cobra.Command) (common.Address, common.Address, bool) {

	senderHex, _ := cmd.Flags().GetString("sender")
	if !common.IsHexAddress(senderHex) {
		log.Fatalf("Invalid sender address: %s", senderHex)
	}
	sender := common.HexToAddress(senderHex)

	entrypointAddrHex, _ := cmd.Flags().GetString("entrypoint")
	if !common.IsHexAddress(entrypointAddrHex) {
		log.Fatalf("Invalid entrypoint address: %s", entrypointAddrHex)
	}
	entrypointAddr := common.HexToAddress(entrypointAddrHex)

	zeroGas, _ := cmd.Flags().GetBool("zerogas")
	return sender, entrypointAddr, zeroGas
}

func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("sender", "", "Sender address in hex")
	cmd.Flags().String("entrypoint", "", "Entrypoint address in hex")
	cmd.Flags().Bool("zerogas", false, "Use zero gas mode")
}

func GetUserOps(userOpJSON string) *model.UserOperation {
	var userOp model.UserOperation
	err := json.Unmarshal([]byte(userOpJSON), &userOp)
	if err != nil {
		log.Fatalf("Error parsing user operation JSON: %v", err)
	}
	return &userOp
}
