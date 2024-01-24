package ethclient

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client wraps the Ethereum client.
type Client struct {
	nodeURL   string
	ethClient *ethclient.Client
}

// NewClient creates a new Ethereum client.
func NewClient(nodeUrl string) *Client {
	client, err := ethclient.Dial(nodeUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	return &Client{nodeURL: nodeUrl, ethClient: client}
}

// GetNodeIDs returns the nonce.
func (c *Client) GetNonce(address common.Address) (*big.Int, error) {
	// Get the Keccak-256 hash of the function signature "getNonce()"
	funcSigBytes := crypto.Keccak256([]byte("getNonce()"))
	// Use only the first 4 bytes
	funcSig := funcSigBytes[:4]
	// Create a new RPC client (for low-level calls)
	rpcClient, err := rpc.Dial(c.nodeURL)
	if err != nil {
		log.Fatalf("Failed to create RPC client: %v", err)
	}
	var result string
	err = rpcClient.CallContext(context.Background(), &result, "eth_call", map[string]interface{}{
		"to":   address.String(),
		"data": "0x" + common.Bytes2Hex(funcSig),
	}, "latest")
	if err != nil {
		log.Fatalf("Failed to call contract: %v", err)
	}
	nonce := new(big.Int)
	nonce.SetString(result[2:], 16)
	return nonce, nil
}

// GetChainID returns the chain id.
func (c *Client) GetChainID(address common.Address) (chainID *big.Int, err error) {
	// Retrieve the chain ID
	chainID, err = c.ethClient.NetworkID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the chain ID: %w", err)
	}
	return chainID, nil
}

// GetCurrentBlockNumber returns the current block number.
func (c *Client) GetCurrentBlockNumber() (uint64, error) {
	header, err := c.ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	return header.Number.Uint64(), nil
}

// GetAccountBalance returns the balance of the specified account.
func (c *Client) GetAccountBalance(accountAddress string) (*big.Int, error) {
	account := common.HexToAddress(accountAddress)
	balance, err := c.ethClient.BalanceAt(context.Background(), account, nil)
	if err != nil {
		return nil, err
	}
	return balance, nil
}
