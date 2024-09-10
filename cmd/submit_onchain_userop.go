package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/abi"
	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	geth "github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stackup-wallet/stackup-bundler/pkg/entrypoint/transaction"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	stackup_userop "github.com/stackup-wallet/stackup-bundler/pkg/userop"
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
		userOp := utils.GetUserOps(cmd)
		SubmitOnChain(userOp)
	},
}

func SubmitOnChain(userOp *model.UserOperation) {
	// Read configuration and initialize necessary components.
	nodeUrl, _, entrypointAddr, eoaSigner := config.ReadConf()
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

	chainID, err := node.EthClient.ChainID(context.Background())
	if err != nil {
		panic(err)
	}

	signUserOp(chainID, entrypointAddr, eoaSigner, unsignedUserOp)

	calldata, err := abi.PrepareHandleOpCalldata([]model.UserOperation{*unsignedUserOp}, eoaSigner.Address)
	if err != nil {
		panic(errors.Wrap(err, "error preparing userOp calldata"))
	}

	fmt.Printf("Entrypoint handleOps calldata: \n%s\n\n", calldata)

	signUserOp(chainID, entrypointAddr, eoaSigner, unsignedUserOp)

	ctx := context.Background()
	submit(ctx, node, chainID, entrypointAddr, eoaSigner, unsignedUserOp)
}

func submit(ctx context.Context, node *ethclient.Client, chainID *big.Int, entrypointAddr common.Address, eoaSigner *signer.EOA, signedUserOp *model.UserOperation) {
	gasParams, err := getGasParams(ctx, node.EthClient)
	if err != nil {
		panic(err)
	}

	opts := createTransactionOpts(node.EthClient, chainID, entrypointAddr, eoaSigner, signedUserOp, gasParams)

	if err := executeUserOperation(opts); err != nil {
		panic(err)
	}
}

func getGasParams(ctx context.Context, rpc *geth.Client) (config.GasParams, error) {
	header, err := rpc.HeaderByNumber(ctx, nil)
	if err != nil {
		return config.GasParams{}, errors.Wrap(err, "failed to get latest block header")
	}
	baseFee := header.BaseFee

	tipCap, err := rpc.SuggestGasTipCap(ctx)
	if err != nil {
		return config.GasParams{}, errors.Wrap(err, "failed to get gas tip cap")
	}

	// legacy gas price calculation
	gasPrice := new(big.Int).Add(baseFee, tipCap)

	return config.GasParams{
		BaseFee:  baseFee,
		Tip:      tipCap,
		GasPrice: gasPrice,
	}, nil
}

func createTransactionOpts(rpcClient *geth.Client, chainID *big.Int, entrypointAddr common.Address, eoaSigner *signer.EOA, signedUserOp *model.UserOperation, gasParams config.GasParams) transaction.Opts {
	stackupUserOp := stackup_userop.UserOperation(*signedUserOp)
	return transaction.Opts{
		Eth:         rpcClient,
		EOA:         eoaSigner,
		ChainID:     chainID,
		EntryPoint:  entrypointAddr,
		Batch:       []*stackup_userop.UserOperation{&stackupUserOp},
		Beneficiary: eoaSigner.Address,
		BaseFee:     gasParams.BaseFee,
		Tip:         gasParams.Tip,
		GasPrice:    gasParams.GasPrice,
		GasLimit:    0,
		NoSend:      false,
		WaitTimeout: 0,
	}
}

func executeUserOperation(opts transaction.Opts) error {
	tx, err := transaction.HandleOps(&opts)
	if err != nil {
		return errors.Wrap(err, "failed to submit user operation on-chain")
	}

	fmt.Printf("UserOperation executed successfully, tx hash: %s\n", tx.Hash().Hex())
	return nil
}
