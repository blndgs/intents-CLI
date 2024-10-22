// userop_processor.go
package cmd

import (
	"context"
	"encoding/json"
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
	// DirectSubmit bypasses the bundler and sends directly to an Ethereum node
	DirectSubmit
)

type UserOpProcessor struct {
	Nodes          config.NodesMap
	BundlerURL     string
	EntrypointAddr common.Address
	Signer         *signer.EOA
	Hashes         []common.Hash
	ChainMonikers  []string
	ChainID        *big.Int
}

func NewUserOpProcessor(nodes config.NodesMap, bundlerURL string, entrypointAddr common.Address, signer *signer.EOA, hashes []common.Hash, chainMonikers []string) *UserOpProcessor {
	return &UserOpProcessor{
		Nodes:          nodes,
		BundlerURL:     bundlerURL,
		EntrypointAddr: entrypointAddr,
		Signer:         signer,
		Hashes:         hashes,
		ChainMonikers:  chainMonikers,
	}
}

func (p *UserOpProcessor) ProcessUserOp(opIdx int, op *model.UserOperation, submissionAction SubmissionType) error {
	chainMoniker := p.ChainMonikers[opIdx]
	chainID := p.Nodes[chainMoniker].ChainID

	sender := op.Sender

	var err error
	//nonce, err = p.Nodes[chainMoniker].Node.EthClient.NonceAt(context.Background(), sender, nil)
	aaNonce, err := ethclient.Get4337Nonce(p.Nodes[chainMoniker].Node.RPCClient, sender)
	if err != nil {
		return fmt.Errorf("error getting nonce for sender %s on chain %s: %w", sender, chainMoniker, err)
	}
	utils.UpdateUserOp(op, aaNonce)

	// Print hash
	utils.PrintHash(op, p.Hashes, p.EntrypointAddr, chainID)

	// Prepare calldata
	calldata, err := abi.PrepareHandleOpCalldata([]model.UserOperation{*op}, p.Signer.Address)
	if err != nil {
		return errors.Wrap(err, "error preparing userOp calldata")
	}
	fmt.Printf("Entrypoint handleOps calldata: \n%s\n\n", calldata)

	if op.Signature != nil {
		p.verifyOpSig(chainID, p.Signer, op)
	}

	if op.Signature == nil {
		p.signUserOp(chainID, op)
	}

	switch submissionAction {
	case Offline:

	case BundlerSubmit:
		// Submit to EIP-4337 bundler
		p.sendUserOp(op)

	case DirectSubmit:
		// Submit directly to Ethereum node
		p.submit(context.Background(), chainID, op)

	default:
		return fmt.Errorf("invalid submission type: %d", submissionAction)
	}

	// Print signature
	utils.PrintSignature(op)

	return nil
}

func (p *UserOpProcessor) signUserOp(chainID *big.Int, signedUserOp *model.UserOperation) {
	if p.BundlerURL == "" {
		panic("bundler URL is not set")
	}

	signedOp, err := userop.Sign(chainID, p.EntrypointAddr, p.Signer, signedUserOp, p.Hashes)
	if err != nil {
		panic(fmt.Errorf("failed signing user operation: %w", err))
	}

	fmt.Printf("Signed userOp:\n%s\n", signedOp)

	// Marshal signedOp into JSON
	jsonBytes, err := json.Marshal(signedOp)
	if err != nil {
		panic(fmt.Errorf("failed marshaling signed operations to JSON: %w", err))
	}

	// Print JSON string
	fmt.Println("Signed UserOp in JSON:", string(jsonBytes))
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

// verifyOpSig verifies the signature of the user operation and then sends it.
func (p *UserOpProcessor) verifyOpSig(chainID *big.Int, signer *signer.EOA, signedUserOp *model.UserOperation) {
	// verify signature
	if signedUserOp.Signature != nil && !userop.VerifySignature(chainID, p.Signer.PublicKey, p.EntrypointAddr, signedUserOp) {
		// signal to generate signature
		signedUserOp.Signature = nil
	}
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
