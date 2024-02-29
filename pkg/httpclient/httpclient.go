package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type JsonRpcRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type JsonRpcResponse struct {
	Jsonrpc string           `json:"jsonrpc"`
	Result  json.RawMessage  `json:"result"`
	Error   *json.RawMessage `json:"error"`
	Id      int              `json:"id"`
}

type RPCErrDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func (r *RPCErrDetail) Error() string {
	return r.Message
}

// SendJsonRpcRequest sends a generic JSON-RPC request to the given URL.
func SendRPCRequest(url, method string, params []interface{}) (json.RawMessage, error) {
	request := JsonRpcRequest{
		Jsonrpc: "2.0",
		Id:      1, // TODO: Implement dynamic ID if necessary
		Method:  method,
		Params:  params,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response JsonRpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	if response.Error != nil {
		var rpcErr RPCErrDetail
		jsonErr := json.Unmarshal(*response.Error, &rpcErr)
		if jsonErr == nil {
			return nil, &rpcErr
		}
		return nil, errors.New(fmt.Sprintf("RPC Error: %s", *response.Error))
	}

	return response.Result, nil
}

// SendUserOp sends the UserOperation to the bundler.
func SendUserOp(bundlerURL string, entryPointAddr common.Address, userOp *model.UserOperation) (json.RawMessage, error) {
	params := []interface{}{userOp, entryPointAddr.Hex()}
	return SendRPCRequest(bundlerURL, "eth_sendUserOperation", params)
}

// GetUserOperationReceipt retrieves the receipt of a UserOperation by its hash.
func GetUserOperationReceipt(bundlerURL string, userOpHash string) (json.RawMessage, error) {
	params := []interface{}{userOpHash}
	resp, err := SendRPCRequest(bundlerURL, "eth_getUserOperationReceipt", params)
	if err != nil {
		var rpcError RPCErrDetail
		if errors.As(err, &rpcError) {
			if rpcError.Code == -32601 {
				println("Cannot query receipt, check that the Ethereum node supports `getLogs`")
			}
		}

		return nil, err
	}

	return resp, nil
}
