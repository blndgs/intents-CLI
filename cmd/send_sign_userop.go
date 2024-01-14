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

var sendAndSignUserOpCmd = &cobra.Command{
	Use:   "sign-send",
	Short: "Sign and send a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read the userOp JSON
		json, _ := cmd.Flags().GetString("sign")
		fmt.Println("Signing userOp:", json)
		nodeUrl, bundlerUrl, eoaSigner := config.ReadConf()
		sender, entrypointAddr, zeroGas := utils.ReadFlags(cmd)
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
		signAndSendUserOp(chainID, bundlerUrl, sender, entrypointAddr, eoaSigner, unsignedUserOp)
	},
}

// signAndSendUserOp signs and send user ops.
func signAndSendUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation) {
	// sign user ops
	signedUserOps, err := userop.Sign(chainID, entryPointAddr, signer, userOp)
	if err != nil {
		panic(err)
	}
	// send user ops
	httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOps)
}

func init() {
	utils.AddCommonFlags(sendAndSignUserOpCmd)
	sendAndSignUserOpCmd.Flags().StringP("sign-send", "c", "", "JSON userOp to be signed and sent")
	if err := sendAndSignUserOpCmd.MarkFlagRequired("sign-send"); err != nil {
		log.Fatal("missing flag: ", err)
	}
}
