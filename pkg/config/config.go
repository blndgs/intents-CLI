package config

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/viper"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

type GasParams struct {
	BaseFee  *big.Int
	Tip      *big.Int
	GasPrice *big.Int
}

type RpcURLSMap map[string]string

const ethNodeUrlPrefix = "eth_node_url_"

// DefaultRPCURLKey Any RPC URL with 'default' in each key is considered as
// the default RPC URL, e.g. ETH_NODE_URL_BSC DEFAULT
const DefaultRPCURLKey = "default"

// ReadConf reads configuration from a .env file and initializes
// necessary variables like node URLs, signer, bundler URL, and entry point address.
// It returns these values and logs configuration details.
func ReadConf() (RpcURLSMap, string, common.Address, *signer.EOA) {
	const signerPrvKey = "SIGNER_PRIVATE_KEY"
	const bundlerUrl = "BUNDLER_URL"
	const epAddr = "ENTRYPOINT_ADDR"

	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	foundDefaultRPCURL := false
	nodeURLs := make(RpcURLSMap)
	for _, key := range viper.AllKeys() {
		// viper.AllKeys() returns all keys in lowercase
		if strings.HasPrefix(key, ethNodeUrlPrefix) {
			if strings.Contains(key, DefaultRPCURLKey) {
				if foundDefaultRPCURL {
					panic(fmt.Errorf("found multiple default RPC URLs"))
				}
				foundDefaultRPCURL = true
				// save the default RPC URL with 'default' as the key
				nodeURLs[DefaultRPCURLKey] = viper.GetString(key)
				continue
			}
			moniker := strings.TrimPrefix(key, ethNodeUrlPrefix)
			nodeURLs[moniker] = viper.GetString(key)
		}
	}

	if !foundDefaultRPCURL {
		panic(fmt.Errorf("no default RPC URL found: Add an environment variable with 'default' in the key, e.g. ETH_NODE_URL_DEFAULT"))
	}

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
	for moniker, url := range nodeURLs {
		fmt.Printf("Node URL for %s: %s\n", moniker, url)
	}

	return nodeURLs, bundlerURL, entryPointAddr, s
}
