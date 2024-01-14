package cmd

import (
	"fmt"
	"log"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

var signUserOpCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a userOp with JSON input",
	Run: func(cmd *cobra.Command, args []string) {
		// Read the userOp JSON
		json, _ := cmd.Flags().GetString("sign")
		fmt.Println("Signing userOp:", json)
		nodeUrl, bundlerUrl, eoaSigner := config.ReadConf()
		sender, entrypointAddr, zeroGas := utils.ReadFlags(cmd)

		ethClient := ethclient.NewClient(nodeUrl)
		nonce, err := ethClient.GetNonce(sender)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := getMockUserOp(sender, nonce, zeroGas)

		chainID, err := ethClient.GetChainID(sender)
		if err != nil {
			panic(err)
		}

		signUserOp(chainID, bundlerUrl, sender, entrypointAddr, eoaSigner, unsignedUserOp)
	},
}

// signAndSendUserOp signs and send user ops.
func signUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, signedUserOp *model.UserOperation) {
	userop.Sign(chainID, entryPointAddr, signer, signedUserOp)
}

func init() {
	utils.AddCommonFlags(signUserOpCmd)
	signUserOpCmd.Flags().StringP("sign", "c", "", "JSON userOp to be signed")
	if err := signUserOpCmd.MarkFlagRequired("sign"); err != nil {
		log.Fatal("missing flag: ", err)
	}
}
