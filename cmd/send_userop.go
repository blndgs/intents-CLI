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
		nodeUrls, bundlerUrl, entrypointAddr, eoaSigner := config.ReadConf()
		userOp := utils.GetUserOps(cmd)
		fmt.Println("send userOp:", userOp)
		hashes := utils.GetHashes(cmd)

		sender := userOp.Sender
		fmt.Println("sender address: ", sender)

		// Initialize Ethereum client and retrieve nonce and chain ID.
		ethClient := ethclient.NewClient(nodeUrls[config.DefaultRPCURLKey])
		nonce, err := ethClient.GetNonce(sender)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := utils.UpdateUserOp(userOp, nonce)

		srcChainID, err := ethClient.EthClient.ChainID(context.Background())
		if err != nil {
			panic(err)
		}

		utils.PrintHash(unsignedUserOp, hashes, entrypointAddr, srcChainID)
		calldata, err := abi.PrepareHandleOpCalldata([]model.UserOperation{*unsignedUserOp}, eoaSigner.Address)
		if err != nil {
			panic(errors.Wrap(err, "error preparing userOp calldata"))
		}

		fmt.Printf("Entrypoint handleOps calldata: \n%s\n\n", calldata)

		sendUserOp(chainID, bundlerUrl, entrypointAddr, eoaSigner, unsignedUserOp)
		utils.PrintSignature(userOp)
	},
}

// sendUserOp verifies the signature of the user operation and then sends it.
func sendUserOp(chainID *big.Int, bundlerUrl string, entryPointAddr common.Address, signer *signer.EOA, signedUserOp *model.UserOperation) {
	// verify signature
	if !userop.VerifySignature(chainID, signer.PublicKey, entryPointAddr, signedUserOp) {
		panic("Signature is invalid")
	}
	// send user ops
	hashResp, err := httpclient.SendUserOp(bundlerUrl, entryPointAddr, signedUserOp)
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
