package cmd

import (
	"fmt"
	"log"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/pkg/httpclient"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
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
		nodeUrl, bundlerUrl, eoaSigner := config.ReadConf()
		sender, entrypointAddr, zeroGas := utils.ReadFlags(cmd)
		// create a eth
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
		sendUserOp(chainID, bundlerUrl, sender, entrypointAddr, eoaSigner, unsignedUserOp)
	},
}

// signAndSendUserOp signs and send user ops.
func sendUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, signedUserOp *model.UserOperation) {
	// verify signature
	if !userop.VerifySignature(chainID, signer.PublicKey, entryPointAddr, signedUserOp) {
		panic("Signature is invalid")
	}
	// send user ops
	httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOp)
}

func init() {
	utils.AddCommonFlags(sendUserOpCmd)
	sendUserOpCmd.Flags().StringP("send", "s", "", "JSON userOp to be sent")
	if err := sendUserOpCmd.MarkFlagRequired("send"); err != nil {
		log.Fatal("missing flag: ", err)
	}
}
