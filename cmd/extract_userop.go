package cmd

import (
	"fmt"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/utils"
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
			panic("extraction does not support hash arguments")
		}

		userOps, err := utils.GetUserOps(cmd)
		if len(userOps) != 1 || err != nil {
			return config.NewError("Provide a single aggregate userOp", err)
		}

		embeddedOp, err := userOps[0].ExtractEmbeddedOp()
		if err != nil {
			panic(fmt.Errorf("error extracting embedded userOp: %s", err))
		}

		fmt.Printf("Source userOp:\n%s\n", userOps[0])
		// Print the formerly aggregated userOp and the extracted userOp
		// set an empty EVM instruction to make it ready for on-chain validation
		if err := userOps[0].SetEVMInstructions([]byte{}); err != nil {
			panic(fmt.Errorf("failed setting the sourceOp EVM instructions: %w", err))
		}
		if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
			return config.NewError("failed to print source userOp", err)
		}

		fmt.Printf("\n===================== Extracted userOp =====================>\n\n")

		fmt.Printf("%s\n", embeddedOp.String())
		// Print the formerly aggregated userOp and the extracted userOp
		// set an empty EVM instruction to make it ready for on-chain validation
		if err := embeddedOp.SetEVMInstructions([]byte{}); err != nil {
			panic(fmt.Errorf("failed setting the embedded EVM instructions: %w", err))
		}
		if err := utils.PrintSignedOpJSON(embeddedOp); err != nil {
			return config.NewError("failed to print extracted userOp", err)
		}

		return nil
	},
}
