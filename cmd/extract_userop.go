package cmd

import (
	"fmt"

	"github.com/blndgs/intents-sdk/utils"
	"github.com/spf13/cobra"
)

// init initializes the extract command and adds it to the root command.
func init() {
	utils.AddCommonFlags(ExtractUserOpCmd)
}

// ExtractUserOpCmd represents the command to sign user operations.
var ExtractUserOpCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract the embedded userOp from an aggregate userOp and prints them.",
	Run: func(cmd *cobra.Command, args []string) {
		providedHashes := utils.GetHashes(cmd)
		if len(providedHashes) > 0 {
			panic("extraction does not support hash arguments")
		}
		signature := utils.GetSignature(cmd)
		if len(signature) > 1 {
			panic("extraction does not support signature arguments")
		}

		userOps := utils.GetUserOps(cmd)
		if len(userOps) != 1 {
			panic("Provide a single aggregate userOp")
		}

		embeddedOp, err := userOps[0].ExtractEmbeddedOp()
		if err != nil {
			panic(fmt.Errorf("error extracting embedded userOp: %s", err))
		}

		// Print the formerly aggregated userOp and the extracted userOp
		fmt.Printf("Source userOp:\n%s\n", userOps[0])

		fmt.Printf("Extracted userOp:\n%s\n", embeddedOp)
	},
}