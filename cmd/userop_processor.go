// userop_processor.go
package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/abi"
	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/pkg/httpclient"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

// SubmissionType represents different methods of submitting a UserOperation
type SubmissionType int

const (
	// Offline mode - only signs or generates or validates but does not submit the UserOperation
	Offline SubmissionType = iota
	// BundlerSubmit sends the UserOperation to an EIP-4337 bundler
	BundlerSubmit
	// BunderSignSubmit signs and sends the UserOperation to an EIP-4337 bundler
	BunderSignSubmit
	// DirectSubmit bypasses the bundler and sends directly to an Ethereum node
	DirectSubmit
)

type UserOpProcessor struct {
	Nodes          config.NodesMap
	BundlerURL     string
	EntrypointAddr common.Address
	Signer         *signer.EOA
	ProvidedHashes []common.Hash
	CachedHashes   []common.Hash
	ChainMonikers  []string
	ChainIDs       []*big.Int
}

func NewUserOpProcessor(userOps []*model.UserOperation, nodes config.NodesMap, bundlerURL string, entrypointAddr common.Address, signer *signer.EOA, hashes []common.Hash, chainMonikers []string) *UserOpProcessor {
	if len(userOps) == 0 {
		panic("userOps is empty")
	}
	if len(userOps) > 1 && len(hashes) > 0 {
		panic("hashes must be empty for multiple UserOperations as they are computed by the userOps")
	}

	chainIDs := make([]*big.Int, len(userOps))
	for opIdx := range userOps {
		chainMoniker := chainMonikers[opIdx]
		chainIDs[opIdx] = nodes[chainMoniker].ChainID
	}

	return &UserOpProcessor{
		Nodes:          nodes,
		BundlerURL:     bundlerURL,
		EntrypointAddr: entrypointAddr,
		Signer:         signer,
		ProvidedHashes: hashes,
		CachedHashes:   make([]common.Hash, 0, len(userOps)),
		ChainIDs:       chainIDs,
		ChainMonikers:  chainMonikers,
	}
}

func (p *UserOpProcessor) setOpHashes(userOps []*model.UserOperation, submissionAction SubmissionType) {
	for i, op := range userOps {
		var hash common.Hash
		if len(p.ProvidedHashes) > i && p.ProvidedHashes[i] != (common.Hash{}) {
			// use the provided hash
			hash = p.ProvidedHashes[i]
			fmt.Printf("Provided UserOp hash: %s for ChainID: %s\n", hash, p.ChainIDs[i])
		} else {
			if submissionAction != BundlerSubmit && submissionAction != DirectSubmit {
				if err := p.Set4337Nonce(op, p.ChainMonikers[i]); err != nil {
					panic(fmt.Errorf("failed setting EIP-4337 nonce: %w", err))
				}
			}

			// compute the hash
			hash = op.GetUserOpHash(p.EntrypointAddr, p.ChainIDs[i])
			fmt.Printf("Generated UserOp hash: %s for ChainID: %s, moniker: %s\n", hash, p.ChainIDs[i], p.ChainMonikers[i])
		}
		// idempotent append
		if len(p.CachedHashes) <= i || p.CachedHashes[i] != hash {
			p.CachedHashes = append(p.CachedHashes, hash)
		}
	}
}

func (p *UserOpProcessor) ProcessUserOps(userOps []*model.UserOperation, submissionAction SubmissionType) error {
	p.setOpHashes(userOps, submissionAction)
	println()
	if len(userOps) > 1 {
		// print the aggregate xChain hash
		fmt.Printf("Aggregate xChain hash: %s\n", userop.GenXHash(p.CachedHashes))
	}

	// Prepare callData
	callData, err := abi.PrepareHandleOpCalldata(*userOps[0], userOps[0].Sender)
	if err != nil {
		return errors.Wrap(err, "error preparing userOp callData")
	}
	fmt.Printf("\nEntrypoint handleOps callData: \n%s\n\n", callData)

	if len(userOps[0].Signature) == 65 {
		userop.CondResetSignature(p.Signer.PublicKey, userOps, p.CachedHashes)
	}

	if len(userOps[0].Signature) == 0 || len(userOps) > 1 {
		p.signUserOps(userOps)
	} else {
		// Print JSON for verified userOp signature
		utils.PrintSignedOpJSON(userOps[0])
	}

	switch submissionAction {
	case Offline:

	case BundlerSubmit:
		// Submit to EIP-4337 bundler
		p.sendUserOp(userOps[0])

	case DirectSubmit:
		// Submit directly to Ethereum node
		p.submit(context.Background(), p.ChainIDs[0], userOps[0])

	default:
		return fmt.Errorf("invalid submission type: %d", submissionAction)
	}

	// Print signature only when the userOp is an Intent operation
	if userOps[0].HasIntent() && len(userOps) == 1 {
		utils.PrintPostIntentSolutionSignature(userOps[0])
	}

	return nil
}

func (p *UserOpProcessor) Set4337Nonce(op *model.UserOperation, chainMoniker string) error {
	sender := op.Sender
	var err error
	aaNonce, err := ethclient.Get4337Nonce(p.Nodes[chainMoniker].Node.RPCClient, sender)
	if err != nil {
		return fmt.Errorf("error getting nonce for sender %s on chain %s: %w", sender, chainMoniker, err)
	}
	utils.UpdateUserOp(op, aaNonce)
	return nil
}

func (p *UserOpProcessor) signUserOps(userOps []*model.UserOperation) {
	if p.BundlerURL == "" {
		panic("bundler URL is not set")
	}

	if err := userop.SignUserOperations(p.Signer, p.CachedHashes, userOps); err != nil {
		panic(fmt.Errorf("failed signing user operations of count:%d %w", len(userOps), err))
	}

	recoveredAddress := userop.RecoverSigner(userop.GenXHash(p.CachedHashes), userOps[0].Signature)

	if len(userOps) == 1 {
		fmt.Printf("Signed userOp:\n%s\n", userOps[0])
		fmt.Printf("\nRecovered address: %s\n\n", recoveredAddress)

		// Marshal signedOp into JSON
		utils.PrintSignedOpJSON(userOps[0])
	} else {
		p.setXCallDataValues(userOps)
		for i, op := range userOps {
			fmt.Printf("\nXChain userOp with xCallData value in the calldata field %d:\n%s\n", i, op)
			fmt.Printf("\nRecovered address: %s\n\n", recoveredAddress)
			utils.PrintSignedOpJSON(op)
		}

		cpyOps := make([]*model.UserOperation, len(userOps))
		for i, op := range userOps {
			cpyOps[i] = new(model.UserOperation)
			*cpyOps[i] = *op
		}
		p.moveXCallDataValues(cpyOps)
		for i, op := range cpyOps {
			fmt.Printf("\nXChain UserOp with xCallData value appended to the signature value: %d:\n", i)
			utils.PrintSignedOpJSON(op)
		}

		// Aggregate the UserOperations
		if err := userOps[0].Aggregate(userOps[1]); err != nil {
			panic(fmt.Errorf("failed to aggregate userOps: %w", err))
		}

		fmt.Printf("\nAggregated userOp:\n%s\n", userOps[0])
		utils.PrintSignedOpJSON(userOps[0])
	}
}

func (p *UserOpProcessor) moveXCallDataValues(userOps []*model.UserOperation) {
	if len(userOps) != 2 {
		panic("only 2 UserOperations are supported")
	}
	if !userOps[0].IsCrossChainOperation() || !userOps[1].IsCrossChainOperation() {
		panic("only cross-chain UserOperations are supported")
	}

	// Append the xCallData values to the UserOperations' signature value and set an empty CallData field value
	if err := userOps[0].SetEVMInstructions([]byte{}); err != nil {
		panic(fmt.Errorf("failed setting the sourceOp EVM instructions: %w", err))
	}
	if err := userOps[1].SetEVMInstructions([]byte{}); err != nil {
		panic(fmt.Errorf("failed setting the destOp EVM instructions: %w", err))
	}
}

// setXCallDataValues sets the xCallData values for the source and destination UserOperations.
// When we extend the x-chain ops to 3 or more, we will update the model's `EncodeCrossChainCallData` and this
// function to set the list of the other userOps hash values
func (p *UserOpProcessor) setXCallDataValues(userOps []*model.UserOperation) {
	if len(userOps) != 2 {
		panic("only 2 UserOperations are supported")
	}

	var err error
	userOps[0].CallData, err = userOps[0].EncodeCrossChainCallData(p.EntrypointAddr, p.CachedHashes[1], true)
	if err != nil {
		panic(fmt.Errorf("failed encoding the sourceOp xCallData value: %w", err))
	}

	userOps[1].CallData, err = userOps[1].EncodeCrossChainCallData(p.EntrypointAddr, p.CachedHashes[0], false)
	if err != nil {
		panic(fmt.Errorf("failed encoding the destOp xCallData value: %w", err))
	}
}

func (p *UserOpProcessor) sendUserOp(signedUserOp *model.UserOperation) {
	// send user ops
	hashResp, err := httpclient.SendUserOp(p.BundlerURL, p.EntrypointAddr, signedUserOp)
	if err != nil {
		panic(err)
	}

	fmt.Printf("sign and send userOps hashResp: %+v\n", hashResp)

	receipt, err := httpclient.GetUserOperationReceipt(p.BundlerURL, hashResp.Solved)
	if err != nil {
		fmt.Println("Error getting UserOperation receipt:", err)
		return
	}

	fmt.Println("UserOperation Receipt:", string(receipt))
}

func (p *UserOpProcessor) submit(ctx context.Context, chainID *big.Int, signedUserOp *model.UserOperation) {
	gasParams, err := getGasParams(ctx, p.Nodes[config.DefaultRPCURLKey].Node.EthClient)
	if err != nil {
		panic(err)
	}

	opts := createTransactionOpts(p.Nodes[config.DefaultRPCURLKey].Node.EthClient, chainID, p.EntrypointAddr, p.Signer, signedUserOp, gasParams)

	if err := executeUserOperation(opts); err != nil {
		panic(fmt.Errorf("failed executing user operation: %w", err))
	}
}
