package cmd

import (
	"fmt"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/spf13/cobra"
)

// init initializes the hash command and adds it to the root command.
func init() {
	utils.AddCommonFlags(HashUserOpCmd)
}

// HashUserOpCmd represents the command to sign user operations.
var HashUserOpCmd = &cobra.Command{
	Use:   "hash",
	Short: "Print the userOp's hash",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodes, _, entrypointAddr, _ := config.ReadConf()

		// Single userOp should be returned
		userOps := utils.GetUserOps(cmd)
		if len(userOps) != 1 {
			panic("Only a single userOp is supported")
		}

		providedHashes := utils.GetHashes(cmd)

		chainMonikers := utils.GetChainMonikers(cmd, nodes, len(userOps))
		genHashes := initHashes(userOps, providedHashes, []*big.Int{nodes[config.DefaultRPCURLKey].ChainID}, entrypointAddr)

		fmt.Printf("\nUserOp hash: %s for %s:%s chain\n\n", genHashes[0], chainMonikers[0], nodes[config.DefaultRPCURLKey].ChainID)
	},
}
