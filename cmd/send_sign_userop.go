// send_sign_userop.go
package cmd

import (
	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/utils"
	"github.com/spf13/cobra"
)

func init() {
	if err := utils.AddCommonFlags(SendAndSignUserOpCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// SendAndSignUserOpCmd represents the command to sign and send user operations.
var SendAndSignUserOpCmd = &cobra.Command{
	Use:   "sign-send",
	Short: "Sign and send userOps with JSON input",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read configuration and initialize necessary components.
		nodes, bundlerURL, entrypointAddr, eoaSigner, _ := config.ReadConf(false)
		userOps, err := utils.GetUserOps(cmd)
		if err != nil {
			return config.NewError("failed to get user operations", err)
		}
		hashes := utils.GetHashes(cmd)
		chainMonikers, _ := utils.GetChainMonikers(cmd, nodes, len(userOps))

		processor, err := NewUserOpProcessor(userOps, nodes, bundlerURL, entrypointAddr, eoaSigner, hashes, chainMonikers)
		if err != nil {
			return config.NewError("failed to create user operation processor", err)
		}

		if err := processor.ProcessUserOps(userOps, BunderSignSubmit); err != nil {
			return config.NewError("failed to process user operations", err)
		}

		return nil
	},
}
