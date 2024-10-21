package cmd

import (
	"context"
	"encoding/json"
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
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
)

// init initializes the signUserOp command and adds it to the root command.
func init() {
	utils.AddCommonFlags(SignUserOpCmd)
}

// SignUserOpCmd represents the command to sign user operations.
var SignUserOpCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodeUrls, _, entrypointAddr, eoaSigner := config.ReadConf()
		userOps := utils.GetUserOps(cmd)

		hashes := utils.GetHashes(cmd)

		sender := userOps[0].Sender

		fmt.Println("sender address: ", sender)

		// Initialize an Ethereum client and retrieve nonce and chain ID.
		ethClient := ethclient.NewClient(nodeUrls[config.DefaultRPCURLKey])
		// get nonce
		nonce, err := ethClient.GetNonce(sender)
		if err != nil {
			panic(err)
		}

		fmt.Println("nonce: ", nonce)
		unsignedUserOp := utils.UpdateUserOp(userOp, nonce)
		fmt.Println("unsignedUserOp: ", unsignedUserOp.String())
		srcChainID, err := ethClient.EthClient.ChainID(context.Background())
		if err != nil {
			panic(err)
		}

		fmt.Printf("\nchain-id:%s\n", srcChainID)
		utils.PrintHash(unsignedUserOp, hashes, entrypointAddr, srcChainID)

		calldata, err := abi.PrepareHandleOpCalldata([]model.UserOperation{*unsignedUserOp}, eoaSigner.Address)
		if err != nil {
			panic(errors.Wrap(err, "error preparing userOp calldata"))
		}

		fmt.Printf("Entrypoint handleOps calldata: \n%s\n\n", calldata)

		// Sign the user operation and prepare it for sending.
		signUserOp(srcChainID, entrypointAddr, eoaSigner, userOp, hashes)
		// Print signature
		utils.PrintSignature(userOp)
	},
}

// signUserOp signs a user operation using the provided parameters and
// prepares it for sending. It utilizes the userop package for signing.
func signUserOp(chainID *big.Int, entryPointAddr common.Address, signer *signer.EOA, signedUserOp *model.UserOperation, hashes []common.Hash) {
	signedOp, err := userop.Sign(chainID, entryPointAddr, signer, signedUserOp, hashes)
	if err != nil {
		panic(err)
	}

	fmt.Printf("signed userOp:\n%s\n", signedOp)

	// Marshal signedOp into JSON
	jsonBytes, err := json.Marshal(signedOp)
	if err != nil {
		panic(fmt.Errorf("error marshaling signed operations to JSON: %v", err))
	}

	// Print JSON string
	fmt.Println("signed UserOps in JSON:", string(jsonBytes))
}
