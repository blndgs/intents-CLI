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

// init initializes the sendAndSignUserOp command and adds it to the root command.
func init() {
	utils.AddCommonFlags(SendAndSignUserOpCmd)
}

// SendAndSignUserOpCmd represents the command to sign and send user operations.
var SendAndSignUserOpCmd = &cobra.Command{
	Use:   "sign-send",
	Short: "Sign and send a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodeUrl, bundlerUrl, entrypointAddr, eoaSigner := config.ReadConf()
		userOp := utils.GetUserOps(cmd)
		fmt.Println("send and sign userOp:", userOp)

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

		fmt.Printf("\nchain-id:%s\n", chainID)
		fmt.Printf("userOp:%s\n\n", unsignedUserOp.GetUserOpHash(entrypointAddr, chainID).String())

		// Sign and send the user operation.
		signAndSendUserOp(chainID, bundlerUrl, sender, entrypointAddr, eoaSigner, unsignedUserOp)
		// Print signature
		utils.PrintSignature(userOp)
	},
}

// signAndSendUserOp signs a user operation and then sends it.
func signAndSendUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation) {
	// Sign user operation.
	signedUserOps, err := userop.Sign(chainID, entryPointAddr, signer, userOp)
	if err != nil {
		panic(err)
	}
	fmt.Println("signedUserOps", signedUserOps)
	// Send user operation.
	resp, err := httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOps)
	if err != nil {
		panic(err)
	}
	fmt.Println("sign and send userOps resp: ", resp)
}
