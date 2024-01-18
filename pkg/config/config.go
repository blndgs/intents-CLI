package config

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/viper"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

// ReadConf reads configuration from a .env file and initializes
// necessary variables like node URL, signer, bundler URL, and entry point address.
// It returns these values and logs configuration details.
func ReadConf() (string, string, common.Address, *signer.EOA) {
	const nodeUrl = "ETH_NODE_URL"
	const signerPrvKey = "SIGNER_PRIVATE_KEY"
	const bundlerUrl = "BUNDLER_URL"
	const epAddr = "ENTRYPOINT_ADDR"

	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	nodeURL := viper.GetString(nodeUrl)
	prvKeyHex := viper.GetString(signerPrvKey)
	s, err := signer.New(prvKeyHex)
	if err != nil {
		panic(fmt.Errorf("fatal signer error: %w", err))
	}
	bundlerURL := viper.GetString(bundlerUrl)

	entryPointAddr := common.HexToAddress(viper.GetString(epAddr))

	fmt.Printf("Signer private key: %s\n", hexutil.Encode(crypto.FromECDSA(s.PrivateKey)))
	fmt.Printf("Public key: %s\n", hexutil.Encode(crypto.FromECDSAPub(s.PublicKey))[4:])
	fmt.Printf("Address: %s\n", s.Address)
	fmt.Printf("Entrypoint Address: %s\n", entryPointAddr)
	return nodeURL, bundlerURL, entryPointAddr, s
}
