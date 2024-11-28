package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-cli/pkg/abi"
	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/pkg/ethclient"
	"github.com/blndgs/intents-cli/pkg/httpclient"
	"github.com/blndgs/intents-cli/pkg/userop"
	"github.com/blndgs/intents-cli/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
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

func NewUserOpProcessor(userOps []*model.UserOperation, nodes config.NodesMap, bundlerURL string, entrypointAddr common.Address, signer *signer.EOA, hashes []common.Hash, chainMonikers []string) (*UserOpProcessor, error) {
	if len(userOps) == 0 {
		return nil, config.NewError("userOps is empty", nil)
	}
	if len(userOps) > 1 && len(hashes) > 0 {
		return nil, config.NewError("hashes must be empty for multiple UserOperations as they are computed by the userOps", nil)
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
	}, nil
}

func (p *UserOpProcessor) setOpHashes(userOps []*model.UserOperation, submissionAction SubmissionType) error {
	for i, op := range userOps {
		var hash common.Hash
		if len(p.ProvidedHashes) > i && p.ProvidedHashes[i] != (common.Hash{}) {
			hash = p.ProvidedHashes[i]
			fmt.Printf("Provided UserOp hash: %s for ChainID: %s\n", hash, p.ChainIDs[i])
		} else if submissionAction != BundlerSubmit && submissionAction != DirectSubmit {
			if err := p.Set4337Nonce(op, p.ChainMonikers[i]); err != nil {
				return config.NewError("failed setting EIP-4337 nonce", err)
			}
		} else if op.IsCrossChainOperation() && len(userOps) == 1 && ((submissionAction == BundlerSubmit && userop.IsAggregate(op)) || submissionAction == DirectSubmit) {
			var xData *model.CrossChainData
			var err error
			if userop.HasXDataInCallData(op) {
				xData, err = model.ParseCrossChainData(op.CallData)
				if err != nil {
					return config.NewError("failed parsing cross-chain data from callData", err)
				}
			} else if userop.HasXDataInSignature(op) {
				xData, err = model.ParseCrossChainData(op.Signature[op.GetSignatureEndIdx():])
				if err != nil {
					return config.NewError("failed parsing cross-chain data from signature", err)
				}
			} else {
				return config.NewError("no cross-chain xData found in cross-chain UserOp's callData or signature", nil)
			}

			hashes := make([]common.Hash, len(xData.HashList))
			for i, h := range xData.HashList {
				if h.IsPlaceholder {
					hashes[i] = op.GetUserOpHash(p.EntrypointAddr, p.ChainIDs[0])
				} else {
					hashes[i] = common.Hash(h.OperationHash)
				}
			}

			hash = userop.GenXHash(hashes)
			fmt.Printf("Generated XChain UserOp hash: %s for ChainID: %s, moniker: %s\n", hash, p.ChainIDs[i], p.ChainMonikers[i])
		}

		if hash == (common.Hash{}) {
			hash = op.GetUserOpHash(p.EntrypointAddr, p.ChainIDs[i])
			fmt.Printf("Generated UserOp hash: %s for ChainID: %s, moniker: %s\n", hash, p.ChainIDs[i], p.ChainMonikers[i])
		}

		if len(p.CachedHashes) <= i || p.CachedHashes[i] != hash {
			p.CachedHashes = append(p.CachedHashes, hash)
		}
	}
	return nil
}

func (p *UserOpProcessor) ProcessUserOps(userOps []*model.UserOperation, submissionAction SubmissionType) error {
	if err := p.setOpHashes(userOps, submissionAction); err != nil {
		return config.NewError("error setting UserOperation hashes", err)
	}
	println()
	if len(userOps) > 1 {
		fmt.Printf("Aggregate xChain hash: %s\n", userop.GenXHash(p.CachedHashes))
	}

	// Prepare callData
	if len(userOps) == 1 {
		callData, err := abi.PrepareHandleOpCalldata(*userOps[0], userOps[0].Sender)
		if err != nil {
			return config.NewError("error preparing userOp callData", err)
		}
		fmt.Printf("\nEntrypoint handleOps callData: \n%s\n\n", callData)
	}

	if len(userOps[0].Signature) == 65 {
		if err := userop.CondResetSignature(p.Signer.PublicKey, userOps, p.CachedHashes); err != nil {
			return config.NewError("failed to verify signature", err)
		}
	}

	if len(userOps[0].Signature) == 0 || len(userOps) > 1 {
		if err := p.signAndPrintUserOps(userOps); err != nil {
			return err
		}
	} else {
		// Print JSON for verified userOp signature
		if submissionAction != DirectSubmit && submissionAction != BundlerSubmit {
			if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
				return config.NewError("failed to print signed userOp JSON", err)
			}
		}
	}

	switch submissionAction {
	case Offline:
		// Print signature only when the userOp is an Intent operation
		if userOps[0].HasIntent() && len(userOps) == 1 {
			utils.PrintPostIntentSolutionSignature(userOps[0])
		}

	case BundlerSubmit:
		// Submit to EIP-4337 bundler
		if err := p.sendUserOp(userOps[0]); err != nil {
			return err
		}

	case DirectSubmit:
		// Submit directly to Ethereum node
		if err := p.submit(context.Background(), p.ChainIDs[0], userOps[0]); err != nil {
			return err
		}

	default:
		return config.NewError(fmt.Sprintf("invalid submission type: %d", submissionAction), nil)
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

func (p *UserOpProcessor) signAndPrintUserOps(userOps []*model.UserOperation) error {
	// UserOperations.
	// For multiple UserOperations, it prints the UserOperations with xCallData
	// values appended to the signature, enabling on-chain execution or simulation
	// without permanent effects.
	// It then prepares the userOperations for sending to the bundler and solver by
	// aggregating the UserOperations and prints the aggregated UserOperation.
	if p.BundlerURL == "" {
		return config.NewError("bundler URL is not set", nil)
	}

	if err := userop.SignUserOperations(p.Signer, p.CachedHashes, userOps); err != nil {
		return config.NewError(fmt.Sprintf("failed signing user operations of count:%d", len(userOps)), err)
	}

	recoveredAddress := userop.RecoverSigner(userop.GenXHash(p.CachedHashes), userOps[0].Signature)

	if len(userOps) == 1 {
		fmt.Printf("Signed userOp:\n%s\n", userOps[0])
		fmt.Printf("\nRecovered address: %s\n\n", recoveredAddress)

		if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
			return config.NewError("failed to print signed userOp JSON", err)
		}
	} else {
		if err := p.setXCallDataValues(userOps); err != nil {
			return err
		}

		for i, op := range userOps {
			fmt.Printf("\nXChain userOp %d:\n%s\n", i, op)
			fmt.Printf("\nRecovered address: %s\n\n", recoveredAddress)
		}

		cpyOps := make([]*model.UserOperation, len(userOps))
		for i, op := range userOps {
			cpyOps[i] = new(model.UserOperation)
			*cpyOps[i] = *op
		}

		if err := p.moveXCallDataValues(cpyOps); err != nil {
			return config.NewError("failed to move xCallData values", err)
		}

		for i, op := range cpyOps {
			fmt.Printf("\nXChain UserOp with xCallData value appended to the signature value: %d:\n", i)
			if err := utils.PrintSignedOpJSON(op); err != nil {
				return config.NewError("failed to print signed userOp JSON", err)
			}
		}

		handleOpsCallData, err := abi.PrepareHandleOpCalldata(*cpyOps[1], cpyOps[1].Sender)
		if err != nil {
			return config.NewError("error preparing userOp handleOpsCallData", err)
		}
		fmt.Printf("\nHandleOps callData value (destination chain): \n%s\n\n", handleOpsCallData)

		if err := userOps[0].Aggregate(userOps[1]); err != nil {
			return config.NewError("failed to aggregate userOps", err)
		}

		fmt.Printf("\nAggregated userOp:\n%s\n", userOps[0])
		if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
			return config.NewError("failed to print signed userOp JSON", err)
		}
	}
	return nil
}

func (p *UserOpProcessor) moveXCallDataValues(userOps []*model.UserOperation) error {
	if len(userOps) != 2 {
		return config.NewError("only 2 UserOperations are supported", nil)
	}
	if !userOps[0].IsCrossChainOperation() || !userOps[1].IsCrossChainOperation() {
		return config.NewError("only cross-chain UserOperations are supported", nil)
	}

	if err := userOps[0].SetEVMInstructions([]byte{}); err != nil {
		return config.NewError("failed setting the sourceOp EVM instructions", err)
	}
	if err := userOps[1].SetEVMInstructions([]byte{}); err != nil {
		return config.NewError("failed setting the destOp EVM instructions", err)
	}
	return nil
}

func (p *UserOpProcessor) setXCallDataValues(userOps []*model.UserOperation) error {
	if len(userOps) != 2 {
		return config.NewError("only 2 UserOperations are supported", nil)
	}

	var err error
	userOps[0].CallData, err = userOps[0].EncodeCrossChainCallData(p.EntrypointAddr, p.CachedHashes[1], true)
	if err != nil {
		return config.NewError("failed encoding the sourceOp xCallData value", err)
	}

	userOps[1].CallData, err = userOps[1].EncodeCrossChainCallData(p.EntrypointAddr, p.CachedHashes[0], false)
	if err != nil {
		return config.NewError("failed encoding the destOp xCallData value", err)
	}
	return nil
}

func (p *UserOpProcessor) sendUserOp(signedUserOp *model.UserOperation) error {
	hashResp, err := httpclient.SendUserOp(p.BundlerURL, p.EntrypointAddr, signedUserOp)
	if err != nil {
		return config.NewError("failed to send user operation", err)
	}

	fmt.Printf("sign and send userOps hashResp: %+v\n", hashResp)

	receipt, err := httpclient.GetUserOperationReceipt(p.BundlerURL, hashResp.Solved)
	if err != nil {
		fmt.Println("Error getting UserOperation receipt:", err)
		return config.NewError("failed to get user operation receipt", err)
	}

	fmt.Println("UserOperation Receipt:", string(receipt))
	return nil
}

func (p *UserOpProcessor) submit(ctx context.Context, chainID *big.Int, signedUserOp *model.UserOperation) error {
	gasParams, err := getGasParams(ctx, p.Nodes[config.DefaultRPCURLKey].Node.EthClient)
	if err != nil {
		return config.NewError("failed to get gas parameters", err)
	}

	opts := createTransactionOpts(p.Nodes[config.DefaultRPCURLKey].Node.EthClient, chainID, p.EntrypointAddr, p.Signer, signedUserOp, gasParams)

	if err := executeUserOperation(opts); err != nil {
		return config.NewError("failed executing user operation", err)
	}
	return nil
}
