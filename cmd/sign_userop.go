package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var signUserOpCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read the userOp JSON
		json, _ := cmd.Flags().GetString("sign")
		fmt.Println("Signing userOp:", json)

		// signUserOp(json)
	},
}

func init() {
	// Define the short and long flag for signing
	signUserOpCmd.Flags().StringP("sign", "c", "", "JSON userOp to be signed")
	if err := signUserOpCmd.MarkFlagRequired("sign"); err != nil {
		log.Fatal("missing flag: ", err)
	}
}
