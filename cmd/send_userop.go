package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var sendUserOpCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read the userOp JSON
		json, _ := cmd.Flags().GetString("send")
		fmt.Println("Sending userOp:", json)

		// sendUserOp(json)
	},
}

func init() {
	// Define the short and long flag for sending
	sendUserOpCmd.Flags().StringP("send", "s", "", "JSON userOp to be sent")
	if err := sendUserOpCmd.MarkFlagRequired("send"); err != nil {
		log.Fatal("missing flag: ", err)
	}
}
