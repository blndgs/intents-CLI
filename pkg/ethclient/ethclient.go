package ethclient

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Client wraps the Ethereum client.
type Client struct {
	ethClient *ethclient.Client
}

// NewClient creates a new Ethereum client.
func NewClient(nodeURL string) *Client {
	client, err := ethclient.Dial(nodeURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	return &Client{ethClient: client}
}

// GetNodeIDs returns the nonce.
func (c *Client) GetNonce(address common.Address) (nonce *big.Int, err error) {
	nonceInt, err := c.ethClient.PendingNonceAt(context.Background(), address)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the nonce: %w", err)
	}
	nonce = big.NewInt(int64(nonceInt))

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
