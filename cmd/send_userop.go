package cmd

import (
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/pkg/httpclient"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

var sendUserOpCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read the userOp JSON
		json, _ := cmd.Flags().GetString("send")
		fmt.Println("Sending userOp:", json)
		nodeUrl, eoaSigner := config.ReadConf()
		sender := common.HexToAddress("0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47")
		entrypointAddrV060 := common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
		bundlerUrl := "http://localhost:4337"
		zeroGas := (len(os.Args) > 1 && (os.Args[1] == "zero" || os.Args[1] == "0")) || len(os.Args) == 1

		ethClient := ethclient.NewClient(nodeUrl)
		nonce, err := ethClient.GetNonce(sender)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := getMockUserOp(sender, nonce, zeroGas)

		chainID, err := ethClient.GetChainID(sender)
		if err != nil {
			panic(err)
		}
		sendUserOp(chainID, bundlerUrl, sender, entrypointAddrV060, eoaSigner, unsignedUserOp)
	},
}

func sendUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation) {
	signedUserOps, err := userop.Sign(chainID, entryPointAddr, signer, userOp)
	if err != nil {
		panic(err)
	}
	httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOps)
}

func init() {
	// Define the short and long flag for sending
	sendUserOpCmd.Flags().StringP("send", "s", "", "JSON userOp to be sent")
	if err := sendUserOpCmd.MarkFlagRequired("send"); err != nil {
		log.Fatal("missing flag: ", err)
	}
}
