package cmd

import (
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
		nodes, _, entrypointAddr, _ := config.ReadConf(false)

		// Single userOp should be returned
		userOps := utils.GetUserOps(cmd)
		if len(userOps) != 1 {
			panic("Only a single userOp is supported")
		}

		providedHashes := utils.GetHashes(cmd)

		p := NewUserOpProcessor(userOps, nodes, "", entrypointAddr, nil, providedHashes, nil)
		p.setOpHashes(userOps, Offline)
	},
}
