// send_sign_userop.go
package cmd

import (
	"fmt"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/spf13/cobra"
)

func init() {
	utils.AddCommonFlags(SignUserOpCmd)
}

// SignUserOpCmd represents the command to sign user operations.
var SignUserOpCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign userOps with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodes, bundlerURL, entrypointAddr, eoaSigner := config.ReadConf(false)
		userOps := utils.GetUserOps(cmd)
		hashes := utils.GetHashes(cmd)
		chainMonikers := utils.GetChainMonikers(cmd, nodes, len(userOps))

		processor := NewUserOpProcessor(userOps, nodes, bundlerURL, entrypointAddr, eoaSigner, hashes, chainMonikers)

		err := processor.ProcessUserOps(userOps, Offline)
		if err != nil {
			panic(err)
		}
	},
}
