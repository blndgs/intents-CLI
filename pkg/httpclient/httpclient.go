package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

type HashesResponse struct {
	Success  bool   `json:"success"`
	Original string `json:"original_hash"`
	Solved   string `json:"solved_hash"`
	Trx      string `json:"trx"`
}

func (r *RPCErrDetail) Error() string {
	return r.Message
}

// SendOpRPCRequest sends a userOp JSON-RPC request to the given Bundler URL.
func SendOpRPCRequest(url, method string, params []interface{}) (*HashesResponse, error) {
	response, err := rpcPost(url, method, params)
	if err != nil {
		return nil, err
	}

	println("response: ", string(response.Result))

	var hashesResp HashesResponse
	if err := json.Unmarshal(response.Result, &hashesResp); err != nil {
		println("Error unmarshalling JSON:", err.Error())
		return nil, err
	}

	return &hashesResp, nil
}

// SendUserOp sends the UserOperation to the bundler.
func SendUserOp(bundlerURL string, entryPointAddr common.Address, userOp *model.UserOperation) (*HashesResponse, error) {
	params := []interface{}{userOp, entryPointAddr.Hex()}
	return SendOpRPCRequest(bundlerURL, "eth_sendUserOperation", params)
}

// SendRPCRequest makes a JSON-RPC request to the given Bundler URL.
func SendRPCRequest(url, method string, params []interface{}) (json.RawMessage, error) {
	response, err := rpcPost(url, method, params)
	if err != nil {
		return nil, err
	}

	println("response: ", string(response.Result))

	return response.Result, nil
}

// rpcPost sends a JSON-RPC request to the given URL.
func rpcPost(url string, method string, params []interface{}) (*JsonRpcResponse, error) {
	request := JsonRpcRequest{
		Jsonrpc: "2.0",
		Id:      1, // TODO: Implement dynamic ID if necessary
		Method:  method,
		Params:  params,
	}

	println("method: ", method)

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response JsonRpcResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
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

	return &response, nil
}

// GetUserOperationReceipt retrieves the receipt of a UserOperation by its hash.
func GetUserOperationReceipt(bundlerURL string, userOpHash string) (json.RawMessage, error) {
	params := []interface{}{userOpHash}
	resp, err := SendRPCRequest(bundlerURL, "eth_getUserOperationReceipt", params)
	if err != nil {
		rpcError := &RPCErrDetail{}
		if errors.As(err, &rpcError) {
			if rpcError.Code == -32601 {
				println("Cannot query receipt, check that the Ethereum node supports `getLogs`")
			}
		}

		return nil, err
	}

	return resp, nil
}
