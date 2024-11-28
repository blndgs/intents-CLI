package cmd

import (
	"fmt"

	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/utils"
	"github.com/spf13/cobra"
)

// init initializes the extract command and adds it to the root command.
func init() {
	if err := utils.AddCommonFlags(ExtractUserOpCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// ExtractUserOpCmd represents the command to sign user operations.
var ExtractUserOpCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract the embedded userOp from an aggregate userOp and prints them.",
	RunE: func(cmd *cobra.Command, args []string) error {
		providedHashes := utils.GetHashes(cmd)
		if len(providedHashes) > 0 {
			return config.NewError("extraction does not support hash arguments", nil)
		}

		userOps, err := utils.GetUserOps(cmd)
		if len(userOps) != 1 || err != nil {
			return config.NewError("Provide a single aggregate userOp", err)
		}

		embeddedOp, err := userOps[0].ExtractEmbeddedOp()
		if err != nil {
			return config.NewError("error extracting embedded userOp", err)
		}

		fmt.Printf("Source userOp:\n%s\n", userOps[0])

		// Set empty EVM instruction to make it ready for on-chain validation
		if err := userOps[0].SetEVMInstructions([]byte{}); err != nil {
			return config.NewError("failed setting the sourceOp EVM instructions", err)
		}

		if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
			return config.NewError("failed to print source userOp", err)
		}

		fmt.Printf("\n===================== Extracted userOp =====================>\n\n")

		fmt.Printf("%s\n", embeddedOp.String())

		// Set empty EVM instruction for extracted op
		if err := embeddedOp.SetEVMInstructions([]byte{}); err != nil {
			return config.NewError("failed setting the embedded EVM instructions", err)
		}

		if err := utils.PrintSignedOpJSON(embeddedOp); err != nil {
			return config.NewError("failed to print extracted userOp", err)
		}

		return nil
	},
}
