package main

import (
	"fmt"
	"os"

	"github.com/blndgs/intents-sdk/cmd"
	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/spf13/cobra"
)

func main() {
	config.ReadConf()

	// Create a new root command
	rootCmd := &cobra.Command{
		Use:   "intents-sdk",
		Short: "Intents SDK Command Line Interface",
		Long:  `Intents SDK CLI provides tools for signing and sending user operations.`,
	}

	// Add commands to the root command
	rootCmd.AddCommand(cmd.SendAndSignUserOpCmd)
	rootCmd.AddCommand(cmd.SendUserOpCmd)
	rootCmd.AddCommand(cmd.SignUserOpCmd)
	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
