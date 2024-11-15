package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	geth "github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
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
		// Read configuration and initialize necessary components.
		nodes, bundlerURL, entrypointAddr, eoaSigner := config.ReadConf()
		userOps := utils.GetUserOps(cmd)
		hashes := utils.GetHashes(cmd)
		chainMonikers := utils.GetChainMonikers(cmd, nodes, len(userOps))

		processor := NewUserOpProcessor(userOps, nodes, bundlerURL, entrypointAddr, eoaSigner, hashes, chainMonikers)

		err := processor.ProcessUserOps(userOps, DirectSubmit)
		if err != nil {
			panic(err)
		}
	},
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
		Beneficiary: signedUserOp.Sender, // beneficiary is the sender of the UserOperation rather than the bundler which is N/A
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
		// Try to cast to DataError interface to extract error data
		var dataErr rpc.DataError
		if errors.As(err, &dataErr) {
			errData := dataErr.ErrorData()
			// Determine the type of errData
			switch data := errData.(type) {
			case string:
				dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
				if err != nil {
					return errors.Wrap(err, "failed to decode error data")
				}
				if epErr, decodeErr := DecodeEntryPointError(dataBytes); decodeErr == nil {
					return errors.Wrap(epErr, "EntryPoint error")
				}
			case []byte:
				if epErr, decodeErr := DecodeEntryPointError(data); decodeErr == nil {
					return errors.Wrap(epErr, "EntryPoint error")
				}
			case hexutil.Bytes:
				if epErr, decodeErr := DecodeEntryPointError(data); decodeErr == nil {
					return errors.Wrap(epErr, "EntryPoint error")
				}
			default:
				fmt.Printf("Unknown ErrorData type: %T\n", data)
			}
		}
		// If all else fails, return the original error
		return errors.Wrap(err, "failed to submit user operation on-chain")
	}

	fmt.Printf("UserOperation executed successfully, tx hash: %s\n", tx.Hash().Hex())
	return nil
}
