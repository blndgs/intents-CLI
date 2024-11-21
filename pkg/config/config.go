package config

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/blndgs/intents-sdk/pkg/ethclient"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/viper"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

type GasParams struct {
	BaseFee  *big.Int
	Tip      *big.Int
	GasPrice *big.Int
}

type ChainNode struct {
	Node      *ethclient.Client
	RPCClient *rpc.Client
	ChainID   *big.Int
	URLStr    string
}

type NodesMap map[string]ChainNode // moniker -> chainID -> node

const ethNodeUrlPrefix = "eth_node_url_"

// DefaultRPCURLKey Any RPC URL with 'default' in each key is considered as
// the default RPC URL, e.g. ETH_NODE_URL_BSC DEFAULT
const DefaultRPCURLKey = "default"

// ReadConf reads configuration from a .env file and initializes
// necessary variables like node URLs, signer, bundler URL, and entry point address.
// It returns these values and logs configuration details.
func ReadConf(quiet bool) (NodesMap, string, common.Address, *signer.EOA) {
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
	nodeURLs := make(NodesMap)
	for _, key := range viper.AllKeys() {
		// viper.AllKeys() returns all keys in lowercase
		if strings.HasPrefix(key, ethNodeUrlPrefix) {
			if strings.Contains(key, DefaultRPCURLKey) {
				if foundDefaultRPCURL {
					panic(fmt.Errorf("found multiple default RPC URLs"))
				}
				foundDefaultRPCURL = true
				// save the default RPC URL with 'default' as the key
				nodeURLs[DefaultRPCURLKey] = initNode(key)
				continue
			}
			moniker := strings.TrimPrefix(key, ethNodeUrlPrefix)
			nodeURLs[moniker] = initNode(key)
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

	if !quiet {
		fmt.Printf("Signer private key: %s\n", hexutil.Encode(crypto.FromECDSA(s.PrivateKey)))
		fmt.Printf("Public key: %s\n", hexutil.Encode(crypto.FromECDSAPub(s.PublicKey))[4:])
		fmt.Printf("Address: %s\n", s.Address)
		fmt.Printf("Entrypoint Address: %s\n", entryPointAddr)
		for moniker := range nodeURLs {
			fmt.Printf("Node moniker: %s url: %s\n", moniker, nodeURLs[moniker].URLStr)
		}
	}

	return nodeURLs, bundlerURL, entryPointAddr, s
}

func initNode(key string) ChainNode {
	urlString := viper.GetString(key)
	node := ethclient.NewClient(urlString)
	chainID, err := node.EthClient.ChainID(context.Background())
	if err != nil {
		panic(fmt.Errorf("failed getting chain ID: %w", err))
	}

	rpcClient, err := rpc.Dial(urlString)
	if err != nil {
		panic(fmt.Errorf("failed dialing the RPC client: %w", err))
	}

	return ChainNode{URLStr: urlString, RPCClient: rpcClient, Node: node, ChainID: chainID}
}
