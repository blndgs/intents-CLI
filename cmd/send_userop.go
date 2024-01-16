package cmd

import (
	"fmt"
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

// init initializes the sendUserOp command and adds it to the root command.
func init() {
	utils.AddCommonFlags(SendUserOpCmd)
}

// SendUserOpCmd represents the command to send user operations.
var SendUserOpCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodeUrl, bundlerUrl, entrypointAddr, eoaSigner := config.ReadConf()
		userOp := utils.GetUserOps(cmd)
		fmt.Println("send userOp:", userOp)

		zeroGas := utils.IsZeroGas(cmd)
		fmt.Println("is zero gas enabled: ", zeroGas)

		sender := userOp.Sender
		fmt.Println("sender address: ", sender)

		// Initialize Ethereum client and retrieve nonce and chain ID.
		ethClient := ethclient.NewClient(nodeUrl)
		nonce, err := ethClient.GetNonce(sender)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := utils.UpdateUserOp(userOp, nonce, zeroGas)

		chainID, err := ethClient.GetChainID(sender)
		if err != nil {
			panic(err)
		}
		sendUserOp(chainID, bundlerUrl, sender, entrypointAddr, eoaSigner, unsignedUserOp)
	},
}

// sendUserOp verifies the signature of the user operation and then sends it.
func sendUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, signedUserOp *model.UserOperation) {
	// verify signature
	if !userop.VerifySignature(chainID, signer.PublicKey, entryPointAddr, signedUserOp) {
		panic("Signature is invalid")
	}
	// send user ops
	resp, err := httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOp)

	if err != nil {
		panic(err)
	}
	fmt.Println("send user Ops response: ", resp)
}
