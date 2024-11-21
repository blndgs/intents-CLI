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
		Use:   "intents-cli",
		Short: "Intents CLI Command Line Interface",
		Long:  `Intents CLI provides tools for signing and submitting user operations.`,
	}

	log.SetOutput(os.Stdout)

	// Add commands to the root command
	rootCmd.AddCommand(cmd.HashUserOpCmd)
	rootCmd.AddCommand(cmd.SendAndSignUserOpCmd)
	rootCmd.AddCommand(cmd.SendUserOpCmd)
	rootCmd.AddCommand(cmd.SignUserOpCmd)
	rootCmd.AddCommand(cmd.OnChainUserOpCmd)
	rootCmd.AddCommand(cmd.RecoverSignerCmd)
	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
