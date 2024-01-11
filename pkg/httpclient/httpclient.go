package httpclient

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
)

type JsonRpcRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// SendUserOp sends the UserOperation to the bundler.
// TODO:: return type define
func SendUserOp(bundlerURL string, entryPointAddr common.Address, userOp *model.UserOperation) (interface{}, error) {
	// TODO:: check id
	request := JsonRpcRequest{
		Jsonrpc: "2.0",
		Id:      45,
		Method:  "eth_sendUserOperation",
		Params:  []interface{}{userOp, entryPointAddr},
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(bundlerURL, "application/json", bytes.NewBuffer(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
