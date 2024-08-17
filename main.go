package main

import (
	"fmt"
	"log"
	"os"

	"github.com/blndgs/intents-sdk/cmd"
	"github.com/spf13/cobra"
)

func main() {
	// Create a new root command
	rootCmd := &cobra.Command{
		Use:   "intents-sdk",
		Short: "Intents SDK Command Line Interface",
		Long:  `Intents SDK CLI provides tools for signing and sending user operations.`,
	}

	log.SetOutput(os.Stdout)

	// Add commands to the root command
	rootCmd.AddCommand(cmd.SendAndSignUserOpCmd)
	rootCmd.AddCommand(cmd.SendUserOpCmd)
	rootCmd.AddCommand(cmd.SignUserOpCmd)
	rootCmd.AddCommand(cmd.OnChainUserOpCmd)
	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
