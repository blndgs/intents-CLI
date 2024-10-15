package cmd

import (
	"context"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/spf13/cobra"
)

// init initializes the hash command and adds it to the root command.
func init() {
	utils.AddCommonFlags(HashUserOpCmd)
}

// HashUserOpCmd represents the command to sign user operations.
var HashUserOpCmd = &cobra.Command{
	Use:   "hash",
	Short: "Print the userOp's hash",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodeUrl, _, entrypointAddr, _ := config.ReadConf()
		userOp := utils.GetUserOps(cmd)
		hashes, err := utils.GetHashes(cmd)
		if err != nil {
			panic(err)
		}

		ethClient := ethclient.NewClient(nodeUrl)

		chainID, err := ethClient.EthClient.ChainID(context.Background())
		if err != nil {
			panic(err)
		}

		// Print signature
		utils.PrintHash(userOp, hashes, entrypointAddr, chainID)
	},
}
