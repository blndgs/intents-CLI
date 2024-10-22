package cmd

import (
	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/spf13/cobra"
)

// init initializes the sendUserOp command and adds it to the root command.
func init() {
	utils.AddCommonFlags(SendUserOpCmd)
}

// SendUserOpCmd represents the command to send user operations.
var SendUserOpCmd = &cobra.Command{
	Use:   "sign-send",
	Short: "Sign and send userOps with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodes, bundlerURL, entrypointAddr, eoaSigner := config.ReadConf()
		userOps := utils.GetUserOps(cmd)
		hashes := utils.GetHashes(cmd)
		chainMonikers := utils.GetChainMonikers(cmd, nodes, len(userOps))

		processor := NewUserOpProcessor(nodes, bundlerURL, entrypointAddr, eoaSigner, hashes, chainMonikers)

		for opIdx, op := range userOps {
			err := processor.ProcessUserOp(opIdx, op, true) // 'true' indicates sending the userOp
			if err != nil {
				panic(err)
			}
		}
	},
}
