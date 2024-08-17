package cmd

import (
	"context"
	"fmt"
	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stackup-wallet/stackup-bundler/pkg/entrypoint/transaction"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	stackup_userop "github.com/stackup-wallet/stackup-bundler/pkg/userop"
	"math/big"
)

// init initializes the submitUserOp command and adds it to the root command.
func init() {
	utils.AddCommonFlags(OnChainUserOpCmd)
}

// OnChainUserOpCmd represents the command to submit user operations on-chain.
var OnChainUserOpCmd = &cobra.Command{
	Use:   "onchain",
	Short: "Submit a signed userOp on-chain bypassing the bundler",
	Run: func(cmd *cobra.Command, args []string) {
		// Read configuration and initialize necessary components.
		nodeUrl, _, entrypointAddr, eoaSigner := config.ReadConf()
		userOp := utils.GetUserOps(cmd)
		fmt.Println("submit userOp:", userOp)

		sender := userOp.Sender
		fmt.Println("sender address: ", sender)

		// Initialize Ethereum client and retrieve nonce and chain ID.
		node := ethclient.NewClient(nodeUrl)
		nonce, err := node.GetNonce(sender)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := utils.UpdateUserOp(userOp, nonce)

		chainID, err := node.GetChainID(sender)
		if err != nil {
			panic(err)
		}

		signUserOp(chainID, entrypointAddr, eoaSigner, unsignedUserOp)

		ctx := context.Background()
		submit(ctx, node, chainID, entrypointAddr, eoaSigner, unsignedUserOp)
	},
}

func submit(ctx context.Context, node *ethclient.Client, chainID *big.Int, entrypointAddr common.Address, eoaSigner *signer.EOA, signedUserOp *model.UserOperation) {
	baseFee, err := node.EthClient.SuggestGasPrice(ctx)
	if err != nil {
		panic(errors.Wrap(err, "failed to get base fee"))
	}

	tip, err := node.EthClient.SuggestGasTipCap(ctx)
	if err != nil {
		panic(errors.Wrap(err, "failed to get gas tip"))
	}

	gasPrice, err := node.EthClient.SuggestGasPrice(ctx)
	if err != nil {
		panic(errors.Wrap(err, "failed to get gas price"))
	}

	stackupUserOp := stackup_userop.UserOperation(*signedUserOp)
	opts := transaction.Opts{
		EOA:         eoaSigner,
		Eth:         node.EthClient,
		ChainID:     chainID,
		EntryPoint:  entrypointAddr,
		Batch:       []*stackup_userop.UserOperation{&stackupUserOp},
		Beneficiary: eoaSigner.Address,
		BaseFee:     baseFee,
		Tip:         tip,
		GasPrice:    gasPrice,
		GasLimit:    0,
		NoSend:      false,
		WaitTimeout: 0,
	}

	// Submit the signed user operation on-chain.
	tx, err := transaction.HandleOps(&opts)
	if err != nil {
		panic(errors.Wrap(err, "failed to submit user operation on-chain"))
	}

	fmt.Printf("UserOperation executed successfully, tx hash: %s\n", tx.Hash().Hex())
}
