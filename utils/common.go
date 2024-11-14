package utils

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
)

type NoncesMap map[string]*big.Int // moniker -> nonce

var (
	ErrInvalidJSONFormat   = fmt.Errorf("invalid JSON format")
	ErrInvalidUserOpFormat = fmt.Errorf("invalid userOp format")
)

// AddCommonFlags adds common flags to the provided Cobra command.
func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("u", "", "User operation JSON")
	cmd.Flags().String("h", "", "List of other cross-chain user operations hashes")
	cmd.Flags().String("c", "", "List of other user operations' Chains")

	if err := cmd.MarkFlagRequired("u"); err != nil {
		panic(err)
	}
}

// GetUserOps parses the 'userop' JSON string or file provided in the command flags
// and returns a slice of UserOperation objects. It processes the callData fields
// before unmarshaling to ensure proper Protobuf formatting.
func GetUserOps(cmd *cobra.Command) []*model.UserOperation {
	userOpInput, _ := cmd.Flags().GetString("u")

	if userOpInput == "" {
		panic("user operation JSON is required")
	}

	var userOpJSON string
	if strings.HasPrefix(userOpInput, "{") || strings.HasPrefix(userOpInput, "[") {
		userOpJSON = userOpInput
	} else if fileExists(userOpInput) {
		fileContent, err := os.ReadFile(userOpInput)
		if err != nil {
			panic(fmt.Errorf("error reading user operation file: %v", err))
		}
		userOpJSON = string(fileContent)
	} else {
		panic("invalid user operation input")
	}

	// Unmarshal the JSON into an interface{} to process callData fields
	var data interface{}
	dec := json.NewDecoder(strings.NewReader(userOpJSON))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		panic(fmt.Errorf("error parsing user operation JSON: %v", err))
	}

	// Process callData fields in the parsed data
	processCallDataFields(data)

	// Marshal the modified data back into JSON
	modifiedJSONBytes, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Errorf("error marshaling modified user operation JSON: %v", err))
	}
	modifiedJSON := string(modifiedJSONBytes)

	// we can unmarshal now into model.UserOperation structs
	return unMarshalOps(modifiedJSON)
}

func unMarshalOps(userOpJSON string) []*model.UserOperation {
	var userOps []*model.UserOperation
	// Determine if the input is a single userOp or an array of userOps
	if strings.HasPrefix(userOpJSON, "[") {
		// Input is an array of userOps
		err := json.Unmarshal([]byte(userOpJSON), &userOps)
		if err != nil {
			panic(fmt.Errorf("error parsing user operations JSON: %v", err))
		}
	} else {
		// Input is a single userOp
		var userOp model.UserOperation
		err := json.Unmarshal([]byte(userOpJSON), &userOp)
		if err != nil {
			panic(fmt.Errorf("error parsing user operation JSON: %v", err))
		}
		userOps = append(userOps, &userOp)
	}
	return userOps
}

// processCallDataFields recursively processes the parsed JSON data to find and modify 'callData' fields.
func processCallDataFields(v interface{}) {
	switch vv := v.(type) {
	case map[string]interface{}:
		for key, val := range vv {
			if key == "callData" {
				if callDataStr, ok := val.(string); ok && callDataStr != "" && callDataStr != "{}" && callDataStr != "0x" {
					if !IsValidHex(callDataStr) {
						// Process callDataStr using ConvJSONNum2ProtoValues
						modifiedCallData, err := ConvJSONNum2ProtoValues(callDataStr)
						if err == nil {
							vv[key] = modifiedCallData
						} else {
							panic(fmt.Errorf("error processing callData: %v", err))
						}
					}
				} else if val == "{}" || val == "" {
					vv[key] = "0x"
				}
			} else {
				// Recursively process nested structures
				processCallDataFields(val)
			}
		}
	case []interface{}:
		for _, item := range vv {
			processCallDataFields(item)
		}
	}
}

// GetHashes parses the 32-byte hash values from the command line flag 'h' and returns a slice of common.Hash.
func GetHashes(cmd *cobra.Command) []common.Hash {
	hashesStr, _ := cmd.Flags().GetString("h")
	if hashesStr == "" {
		return nil // Return nil if the "h" flag is not provided
	}

	hashes := strings.Split(hashesStr, " ")
	var parsedHashes []common.Hash

	for _, hashStr := range hashes {
		hashStr = strings.TrimPrefix(hashStr, "0x")
		if len(hashStr) != 64 {
			return nil
		}

		hashBytes, err := hex.DecodeString(hashStr)
		if err != nil {
			return nil
		}

		var hash common.Hash
		copy(hash[:], hashBytes)
		parsedHashes = append(parsedHashes, hash)
	}

	return parsedHashes
}

// GetChainMonikers parses the network moniker or numeric chain-id value from the command line
// flag 'c' and returns a slice of chain monikers. The number of chains provided must
// match the number of userOps and belong to the initialized nodesMap. If a chain ID
// is provided instead of a moniker, it will be matched against the chain IDs in nodesMap.
func GetChainMonikers(cmd *cobra.Command, nodesMap config.NodesMap, opsCount int) []string {
	var parsedChains = []string{config.DefaultRPCURLKey}
	chainsStr, _ := cmd.Flags().GetString("c")
	if chainsStr == "" && opsCount > 1 {
		panic("chains flag is required when multiple userOps were provided")
	}
	if chainsStr == "" {
		return parsedChains
	}

	chains := strings.Split(chainsStr, " ")
	if len(chains) > opsCount {
		panic(fmt.Errorf("number of chains provided is more than the number of user operations"))
	}
	if len(chains) > len(nodesMap) {
		panic(fmt.Errorf("number of chains provided is more than the number of nodes in the configuration map"))
	}
	if len(chains) < opsCount-1 && opsCount > 1 {
		panic(fmt.Errorf("number of chains provided is less than the number of user operations"))
	}

	for _, chain := range chains {
		if strings.ToLower(chain) == config.DefaultRPCURLKey {
			panic(fmt.Errorf("chain %s has already been added in the first position", chain))
		}
		if _, ok := nodesMap[chain]; ok {
			parsedChains = append(parsedChains, chain)
		} else {
			// Check if the chain is a chain ID
			for moniker, node := range nodesMap {
				// Check if the chain ID matches the chain ID of the node
				if node.ChainID.String() == chain {
					parsedChains = append(parsedChains, moniker)
					continue
				}
			}
			panic(fmt.Errorf("chain %s is not found in the configuration map nodes", chain))
		}
	}

	return parsedChains
}

// UpdateUserOp sets the nonce value and 4337 default gas limits if they are zero.
func UpdateUserOp(userOp *model.UserOperation, nonce *big.Int) *model.UserOperation {
	zero := big.NewInt(0)

	if userOp.CallGasLimit.Cmp(zero) == 0 {
		userOp.CallGasLimit = big.NewInt(65536)
	}
	if userOp.VerificationGasLimit.Cmp(zero) == 0 {
		userOp.VerificationGasLimit = big.NewInt(65536)
	}
	if userOp.PreVerificationGas.Cmp(zero) == 0 {
		userOp.PreVerificationGas = big.NewInt(70000)
	}

	userOp.Nonce = nonce
	return userOp
}

// PrintSignature prints the signature + hex encoded intent JSON (calldata).
func PrintSignature(userOp *model.UserOperation) {
	fmt.Printf("\nSignature value after solution:\n%s\n",
		hexutil.Encode(userOp.Signature)+hex.EncodeToString(userOp.CallData))
}

// PrintHash prints the userOp hash value.
func PrintHash(userOps []*model.UserOperation, hashes []common.Hash, entrypoint common.Address, chainIDs []*big.Int) {
	if len(hashes) > 0 && len(userOps) == 1 {
		// Print the x-chain hash value of the provided userOp and the list of other cross-chain user operations hashes
		fmt.Printf("\nUserOp's Hash value:\n%s\n", userop.GetXHash(userOps[0], hashes, entrypoint, chainIDs))
	} else if len(hashes) == 0 && len(userOps) == 1 {
		// Print the single userOp Hash
		// or
		// Print the multiple userOps x-chain Hash
		fmt.Printf("\nUserOp(s) Hash value:\n%s\n", userop.GetOpsHash(userOps, entrypoint, chainIDs))
	} else {
		panic("invalid userOp and hashes combination")
	}
}

// IsValidHex checks if a string is a valid hexadecimal representation.
func IsValidHex(s string) bool {
	re := regexp.MustCompile(`^0x[0-9a-fA-F]*$`)
	return re.MatchString(s)
}

// ConvJSONNum2ProtoValues converts numeric values in a JSON string to base64 encoded BigInt representations.
// It specifically looks for fields named "value" and converts their numeric contents.
//
// Parameters:
//   - jsonStr: A valid JSON string containing numeric values to be converted
//
// Returns:
//   - string: The modified JSON with converted values
//   - error: Any error encountered during processing
func ConvJSONNum2ProtoValues(jsonStr string) (string, error) {
	var data interface{}

	// Create a decoder that preserves number precision
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()

	// Decode the JSON string
	if err := dec.Decode(&data); err != nil {
		return "", err
	}

	// Process all values recursively
	processMapValues(data)

	// Marshal the processed data back to JSON
	outputBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(outputBytes), nil
}

// processMapValues recursively processes a decoded JSON structure, converting numeric "value" fields
// to their base64 encoded BigInt representation.
//
// Parameters:
//   - v: interface{} representing a JSON structure (can be map, slice, or primitive)
func processMapValues(v interface{}) {
	switch vv := v.(type) {
	case map[string]interface{}:
		// Process each key-value pair in the map
		for key, val := range vv {
			if key == "value" {
				// Convert numeric values when the key is "value"
				switch num := val.(type) {
				case json.Number:
					vv[key] = convertNumberToBase64(num.String())
				case string:
					// Try to parse the string as a number
					if _, ok := new(big.Int).SetString(num, 10); ok {
						vv[key] = convertNumberToBase64(num)
					}
				}
			} else {
				// Recursively process nested structures
				processMapValues(val)
			}
		}
	case []interface{}:
		// Process each item in the array
		for _, item := range vv {
			processMapValues(item)
		}
	}
}

// convertNumberToBase64 converts a numeric string to its base64 encoded BigInt representation.
//
// Parameters:
//   - numStr: string representing a numeric value
//
// Returns:
//   - string: base64 encoded representation of the number
func convertNumberToBase64(numStr string) string {
	// Convert string number to BigInt
	bigInt := new(big.Int)
	bigInt.SetString(numStr, 10)

	// Convert BigInt to bytes and then to base64
	bytes := bigInt.Bytes()
	base64Value := base64.StdEncoding.EncodeToString(bytes)
	return base64Value
}

// fileExists checks if a file exists at the given path.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}
