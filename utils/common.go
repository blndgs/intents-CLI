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
	"unicode"
	"unicode/utf8"

	"github.com/blndgs/intents-sdk/pkg/config"
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

// sanitizeUserOpJSON cleans up the input JSON string
func sanitizeUserOpJSON(userOpJSON string) string {
	// Trim leading and trailing whitespace and control characters
	userOpJSON = strings.TrimFunc(userOpJSON, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})

	// This will match quoted strings followed by colon; presumes that whitespace is not allowed in field names
	fieldNameRegex := `"([^"]+)":`

	// To clean up spaces in field names but preserve the values:
	userOpJSON = regexp.MustCompile(fieldNameRegex).ReplaceAllStringFunc(userOpJSON, func(match string) string {
		// Remove spaces from the field name part while preserving the quotes and colon
		cleaned := regexp.MustCompile(`\s+`).ReplaceAllString(match, "")
		return cleaned
	})

	// Remove BOM character if present
	userOpJSON = strings.TrimPrefix(userOpJSON, "\uFEFF")

	if !utf8.ValidString(userOpJSON) {
		userOpJSON = strings.ToValidUTF8(userOpJSON, "")
	}

	return userOpJSON
}

// GetUserOps parses the 'userop' JSON string or file provided in the command flags
// and returns a slice of UserOperation objects. It processes numeric values
// before unmarshaling to ensure proper formatting.
func GetUserOps(cmd *cobra.Command) []*model.UserOperation {
	userOpInput, _ := cmd.Flags().GetString("u")
	if userOpInput == "" {
		panic("user operation JSON is required")
	}
	userOpInput = strings.TrimSpace(userOpInput)

	var jsonContent string
	if strings.HasPrefix(userOpInput, "{") || strings.HasPrefix(userOpInput, "[") {
		jsonContent = userOpInput
	} else if fileExists(userOpInput) {
		fileContent, err := os.ReadFile(userOpInput)
		if err != nil {
			panic(fmt.Errorf("error reading user operation file: %v", err))
		}
		jsonContent = string(fileContent)
	} else {
		panic("invalid user operation input")
	}

	sanitizedJSON := sanitizeUserOpJSON(jsonContent)

	// Unmarshal the JSON into an interface{} to process fields
	var data interface{}
	dec := json.NewDecoder(strings.NewReader(sanitizedJSON))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		panic(fmt.Errorf("error parsing user operation JSON: %v", err))
	}

	// Process numeric fields
	processNumericFields(data)

	// Process callData field
	processCallDataFields(data)

	// Marshal the modified data back into JSON
	modifiedJSONBytes, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Errorf("error marshaling modified user operation JSON: %v", err))
	}
	modifiedJSON := string(modifiedJSONBytes)

	// Unmarshal into model.UserOperation structs
	return unMarshalOps(modifiedJSON)
}

// unMarshalOps unmarshals the modified JSON into UserOperation structs
func unMarshalOps(userOpJSON string) []*model.UserOperation {
	var userOps []*model.UserOperation
	// Determine if the input is a single userOp or an array of userOps
	if strings.HasPrefix(userOpJSON, "[") {
		// Input is an array of userOps
		err := json.Unmarshal([]byte(userOpJSON), &userOps)
		if err != nil {
			fmt.Println(userOpJSON)
			panic(fmt.Errorf("error parsing user operations JSON: %v", err))
		}
	} else {
		// Input is a single userOp
		var userOp model.UserOperation
		err := json.Unmarshal([]byte(userOpJSON), &userOp)
		if err != nil {
			fmt.Println(userOpJSON)
			panic(fmt.Errorf("error parsing user operation JSON: %v", err))
		}
		userOps = append(userOps, &userOp)
	}
	return userOps
}

// processNumericFields converts numeric values in the UserOp fields to hex strings with '0x' prefix
func processNumericFields(v interface{}) {
	if vv, ok := v.(map[string]interface{}); ok {
		for key, val := range vv {
			if key != "initCode" && key != "paymasterAndData" && key != "signature" {
				switch valTyped := val.(type) {
				case json.Number:
					bigInt, ok := new(big.Int).SetString(valTyped.String(), 10)
					if ok {
						vv[key] = "0x" + bigInt.Text(16)
					}
				case string:
					if valTyped == "" {
						vv[key] = "0x"
					} else if IsNumericString(valTyped) {
						bigInt, ok := new(big.Int).SetString(valTyped, 10)
						if ok {
							vv[key] = "0x" + bigInt.Text(16)
						}
					} else if valTyped == "0" {
						vv[key] = "0x0"
					}
				default:
					// Recursively process nested structures
					processNumericFields(val)
				}
			}
		}
	}
}

// IsNumericString checks if a string represents a numeric value (big.Int)
func IsNumericString(s string) bool {
	_, ok := new(big.Int).SetString(s, 10)
	return ok
}

// processCallDataFields processes the 'callData' field to ensure it is correctly formatted
func processCallDataFields(v interface{}) {
	if vv, ok := v.(map[string]interface{}); ok {
		for key, val := range vv {
			if key == "callData" {
				if callDataStr, ok := val.(string); ok {
					if callDataStr == "" || callDataStr == "{}" {
						vv[key] = "0x"
					} else if callDataStr == "0" {
						vv[key] = "0x0"
					} else if IsValidHex(callDataStr) {
						// Already valid hex string, do nothing
					} else {
						// Process callDataStr using ConvJSONNum2ProtoValues
						modifiedCallData, err := ConvJSONNum2ProtoValues(callDataStr)
						if err == nil {
							vv[key] = modifiedCallData
						} else {
							panic(fmt.Errorf("error processing callData: %v", err))
						}
					}
				}
			} else {
				// Recursively process nested structures
				processCallDataFields(val)
			}
		}
	} else if vv, ok := v.([]interface{}); ok {
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
			var found bool
			for moniker, node := range nodesMap {
				// Check if the chain ID matches the chain ID of the node
				if node.ChainID.String() == chain {
					parsedChains = append(parsedChains, moniker)
					found = true
					break
				}
			}
			if !found {
				panic(fmt.Errorf("chain %s not found in the nodes configuration", chain))
			}
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

func PrintSignedOpJSON(userOp *model.UserOperation) {
	jsonBytes, err := json.Marshal(userOp)
	if err != nil {
		panic(fmt.Errorf("failed marshaling signed operations to JSON: %w", err))
	}

	// Print signed Op JSON
	if userOp.IsCrossChainOperation() && len(userOp.Signature) > 65 {
		_, err := model.ParseCrossChainData(userOp.Signature[65:])
		if err != nil {
			// The embedded userOp is appended to the signature value
			fmt.Println("Signed Aggregate XChain UserOp in JSON:", string(jsonBytes))
		} else {
			// xCallData value is appended to the signature value
			fmt.Println(string(jsonBytes))
		}
	} else if userOp.IsCrossChainOperation() {
		fmt.Println("Signed XChain UserOp in JSON:", string(jsonBytes))
	} else {
		fmt.Println("Signed UserOp in JSON:", string(jsonBytes))
	}
}

// PrintPostIntentSolutionSignature prints the signature + hex encoded intent JSON (calldata).
func PrintPostIntentSolutionSignature(userOp *model.UserOperation) {
	if len(userOp.Signature) >= 65 {
		fmt.Printf("\nSignature value after solution:\n%s\n",
			hexutil.Encode(userOp.Signature[:65])+hex.EncodeToString(userOp.CallData))
	}
}

// IsValidHex checks if a string is a valid hexadecimal representation.
func IsValidHex(s string) bool {
	re := regexp.MustCompile(`^0x[0-9a-fA-F]*$`)
	return re.MatchString(s)
}

// ConvJSONNum2ProtoValues converts numeric values in a JSON string to base64 encoded BigInt representations.
// It specifically looks for fields named "value" and converts their numeric contents.
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
					} else if num == "" {
						vv[key] = "0x"
					} else if num == "0" {
						vv[key] = "0x0"
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
