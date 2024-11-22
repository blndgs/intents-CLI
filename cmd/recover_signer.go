package cmd

import (
	"fmt"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

// init initializes the recover command and adds it to the root command.
func init() {
	utils.AddCommonFlags(RecoverSignerCmd)
}

// RecoverSignerCmd represents the command to sign user operations.
var RecoverSignerCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover the userOp signature's signer. Signatures with appended xData are supported. with 1 or more hashes and a signature",
	Run: func(cmd *cobra.Command, args []string) {
		_, _, _, eoaSigner := config.ReadConf(true)

		providedHashes := utils.GetHashes(cmd)
		signature := utils.GetSignature(cmd)

		if len(providedHashes) == 0 || len(signature) == 0 {
			fmt.Printf("No hashes or signature provided")
			return
		}

		// set a minimal user operation to get the signature end index
		op := model.UserOperation{}
		op.Signature = signature
		endIdx := op.GetSignatureEndIdx()

		// Validate the signature
		if len(providedHashes) == 1 && len(signature) > model.KernelSignatureLength {
			// Check if the signature has xData appended
			if !model.IsCrossChainData(signature[endIdx:], model.MinOpCount, model.MaxOpCount) {
				fmt.Printf("No xData value in the signature field and hashes provided\n")
				return
			}
			xData, err := model.ParseCrossChainData(signature[op.GetSignatureEndIdx():])
			if err != nil {
				fmt.Printf("Error parsing xData value from the signature: %s\n", err)
				return
			}
			hashList := make([]common.Hash, len(xData.HashList))
			for i, hash := range xData.HashList {
				if hash.IsPlaceholder {
					hashList[i] = providedHashes[0]
				} else {
					hashList[i] = common.Hash(hash.OperationHash)
				}
			}
			providedHashes = hashList
		}

		recoverSigner(providedHashes, signature, endIdx, eoaSigner.Address.String())
	},
}

func recoverSigner(providedHashes []common.Hash, signature []byte, sigEndIdx int, eoaSigner string) {
	hash := userop.GenXHash(providedHashes)
	if len(providedHashes) > 1 {
		fmt.Printf("XChain hash: %s\n", hash)
	}
	recovered := userop.RecoverSigner(hash, signature[:sigEndIdx])
	if len(signature) > model.KernelSignatureLength {
		fmt.Printf("XChain Signature is valid for recovered: %s\n", recovered)
	} else {
		fmt.Printf("Signature is valid for recovered: %s\n", recovered)
	}

	if recovered != eoaSigner {
		fmt.Printf("\nRecovered signer does not match the configured EOA signer: %s\n", eoaSigner)
		fmt.Printf("                                                             *\n")
	}
}
