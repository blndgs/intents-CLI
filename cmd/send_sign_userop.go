package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/abi"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/pkg/httpclient"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
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
		hashes, err := utils.GetHashes(cmd)
		if err != nil {
			panic(err)
		}

		sender := userOp.Sender
		fmt.Println("sender address: ", sender)
		// Initialize Ethereum client and retrieve nonce and chain ID.
		ethClient := ethclient.NewClient(nodeUrl)

		nonce, err := ethClient.GetNonce(sender)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := utils.UpdateUserOp(userOp, nonce)

		chainID, err := ethClient.EthClient.ChainID(context.Background())
		if err != nil {
			panic(err)
		}

		fmt.Printf("\nchain-id:%s\n", chainID)
		utils.PrintHash(unsignedUserOp, hashes, entrypointAddr, chainID)

		calldata, err := abi.PrepareHandleOpCalldata([]model.UserOperation{*unsignedUserOp}, eoaSigner.Address)
		if err != nil {
			panic(errors.Wrap(err, "error preparing userOp calldata"))
		}

		fmt.Printf("Entrypoint handleOps calldata: \n%s\n\n", calldata)

		// Sign and send the user operation.
		signAndSendUserOp(chainID, bundlerUrl, entrypointAddr, eoaSigner, unsignedUserOp)
		// Print signature
		utils.PrintSignature(userOp)
	},
}

// signAndSendUserOp signs a user operation and then sends it.
func signAndSendUserOp(chainID *big.Int, bundlerUrl string, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation) {
	// Sign user operation.
	signedUserOps, err := userop.Sign(chainID, entryPointAddr, signer, userOp)
	if err != nil {
		panic(err)
	}
	fmt.Println("signedUserOps", signedUserOps)
	// Send user operation.
	hashResp, err := httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOps)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sign and send userOps hashResp: %+v\n", hashResp)

	receipt, err := httpclient.GetUserOperationReceipt(bundlerUrl, hashResp.Solved)
	if err != nil {
		fmt.Println("Error getting UserOperation receipt:", err)
		return
	}
	fmt.Println("UserOperation Receipt:", string(receipt))
}
