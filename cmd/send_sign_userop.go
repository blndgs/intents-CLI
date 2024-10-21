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
		nodes, bundlerUrl, entrypointAddr, eoaSigner := config.ReadConf()
		userOps := utils.GetUserOps(cmd)
		fmt.Println("send and sign userOp:", userOps)
		hashes := utils.GetHashes(cmd)
		chainMonikers := utils.GetChainMonikers(cmd, nodes, len(userOps))

		sender := userOps[0].Sender
		fmt.Println("sender address: ", sender)

		for opIdx, op := range userOps {
			// Retrieve the chain nonces for the sender address.
			updateNonces(sender, op, chainMonikers, nodes)

			utils.PrintHash(op, hashes, entrypointAddr, nodes[chainMonikers[opIdx]].ChainID)
			calldata, err := abi.PrepareHandleOpCalldata([]model.UserOperation{*op}, eoaSigner.Address)
			if err != nil {
				panic(errors.Wrap(err, "error preparing userOp calldata"))
			}
			fmt.Printf("Entrypoint handleOps calldata: \n%s\n\n", calldata)
			// Sign and send the user operation.
			signAndSendUserOp(nodes[chainMonikers[opIdx]].ChainID, bundlerUrl, entrypointAddr, eoaSigner, op, hashes)
			// Print signature
			utils.PrintSignature(op)
		}

	},
}

func updateNonces(sender common.Address, op *model.UserOperation, chainMonikers []string, nodes config.NodesMap) {
	for _, chainMoniker := range chainMonikers {
		nonce, err := nodes[chainMoniker].Node.EthClient.NonceAt(context.Background(), sender, nil)
		if err != nil {
			panic(fmt.Errorf("error getting nonce for sender %s on chain %s: %w", sender, chainMoniker, err))
		}
		utils.UpdateUserOp(op, new(big.Int).SetUint64(nonce))
	}
}

// signAndSendUserOp signs a user operation and then sends it.
func signAndSendUserOp(chainID *big.Int, bundlerUrl string, entryPointAddr common.Address, signer *signer.EOA, userOp *model.UserOperation, hashes []common.Hash) {
	signUserOp(chainID, entryPointAddr, signer, userOp, hashes)

	sendUserOp(bundlerUrl, entryPointAddr, userOp) // Send user operation.
}
