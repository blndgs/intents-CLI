package cmd

import (
	"fmt"
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
		nodeUrl, bundlerUrl, entrypointAddr, eoaSigner := config.ReadConf()
		userOp := utils.GetUserOps(cmd)

		fmt.Println("sign userOp:", userOp.String())

		zeroGas := utils.IsZeroGas(cmd)

		fmt.Println("is zero gas enabled: ", zeroGas)

		sender := userOp.Sender

		fmt.Println("sender address: ", sender)

		// Initialize Ethereum client and retrieve nonce and chain ID.
		ethClient := ethclient.NewClient(nodeUrl)
		nonce, err := ethClient.GetNonce(sender)

		fmt.Println("nonce: ", nonce)
		if err != nil {
			panic(err)
		}
		unsignedUserOp := utils.UpdateUserOp(userOp, nonce, zeroGas)
		fmt.Println("unsignedUserOp: ", unsignedUserOp.String())
		chainID, err := ethClient.GetChainID(sender)
		fmt.Println("chainID: ", chainID)
		if err != nil {
			panic(err)
		}

		// Sign the user operation and prepare it for sending.
		signUserOp(chainID, bundlerUrl, sender, entrypointAddr, eoaSigner, userOp)
	},
}

// signUserOp signs a user operation using the provided parameters and
// prepares it for sending. It utilizes the userop package for signing.
func signUserOp(chainID *big.Int, bundlerUrl string, address, entryPointAddr common.Address, signer *signer.EOA, signedUserOp *model.UserOperation) {
	signedOps, err := userop.Sign(chainID, entryPointAddr, signer, signedUserOp)
	if err != nil {
		panic(err)
	}
	fmt.Println("signed UserOps:", signedOps)
}
