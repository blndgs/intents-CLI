package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
)

type NoncesMap map[string]*big.Int // moniker -> nonce

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
// and returns a UserOperation object. It panics if the JSON string is empty,
// the file can't be read, or the JSON can't be parsed.
func GetUserOps(cmd *cobra.Command) []*model.UserOperation {
	userOpInput, _ := cmd.Flags().GetString("u")

	if userOpInput == "" {
		panic("user operation JSON is required")
	}

	var userOpJSON string
	if userOpInput[0] == '{' || userOpInput[0] == '[' {
		callDataEncoded, err := ProcessCallDataUsingBigInt(userOpInput)
		if err != nil {
			panic(fmt.Errorf("error encoding callData: %v", err))
		}
		userOpJSON = callDataEncoded
	} else if fileExists(userOpInput) {
		fileContent, err := os.ReadFile(userOpInput)
		if err != nil {
			panic(fmt.Errorf("error reading user operation file: %v", err))
		}
		callDataEncoded, err := ProcessCallDataUsingBigInt(string(fileContent))
		if err != nil {
			panic(fmt.Errorf("error encoding callData: %v", err))
		}
		userOpJSON = callDataEncoded
	} else {
		panic("invalid user operation input")
	}

	var userOps []*model.UserOperation
	if userOpJSON[0] == '[' {
		err := json.Unmarshal([]byte(userOpJSON), &userOps)
		if err != nil {
			panic(fmt.Errorf("error parsing user operations JSON: %v", err))
		}
	} else {
		var userOp model.UserOperation
		err := json.Unmarshal([]byte(userOpJSON), &userOp)
		if err != nil {
			panic(fmt.Errorf("error parsing user operation JSON: %v", err))
		}
		userOps = append(userOps, &userOp)
	}

	return userOps
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
	chainsStr, _ := cmd.Flags().GetString("c")
	if chainsStr == "" && opsCount > 1 {
		panic("chains flag is required when multiple userOps were provided")
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

	var parsedChains = make([]string, 0, len(chains)+1)
	// add the default node chain
	if len(parsedChains) < opsCount {
		parsedChains = append(parsedChains, config.DefaultRPCURLKey)
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
func PrintHash(userOp *model.UserOperation, hashes []common.Hash, entrypoint common.Address, chainID *big.Int) {
	if len(hashes) > 0 {
		// Print the hash value of the userOp and the list of other cross-chain user operations hashes
		fmt.Printf("\nUserOp's Hash value:\n%s\n", userop.GetXHash(userOp, hashes, entrypoint, []*big.Int{chainID}).String())
	} else {
		// Print the hash value of the userOp
		fmt.Printf("\nUserOp's Hash value:\n%s\n", userop.GetOpsHash([]*model.UserOperation{userOp}, entrypoint, []*big.Int{chainID}).String())
	}
}

// ProcessCallDataUsingBigInt convert the int to ProtoBigInt.
func ProcessCallDataUsingBigInt(jsonData string) (string, error) {
	// Use regex to trim whitespace before or after " quote characters
	re := regexp.MustCompile(`\s*"\s*`)
	jsonData = re.ReplaceAllStringFunc(jsonData, func(match string) string {
		return `"`
	})
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return "", err
	}

	if callData, ok := data["callData"].(string); ok && callData != "" && callData != "{}" && callData != "0x" {
		if !isValidHex(callData) {
			var callDataMap map[string]interface{}
			err := json.Unmarshal([]byte(callData), &callDataMap)
			if err != nil {
				return "", err
			}

			err = convertToBigInt(callDataMap)
			if err != nil {
				return "", err
			}

			modifiedCallData, err := json.Marshal(callDataMap)
			if err != nil {
				return "", err
			}

			data["callData"] = string(modifiedCallData)
		}
	}

	// If callData is empty, set it to valid 0 hex value "0x"
	if data["callData"] == "{}" || data["callData"] == "" {
		data["callData"] = "0x"
	}

	encodedBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(encodedBytes), nil
}

func isValidHex(s string) bool {
	if !strings.HasPrefix(s, "0x") {
		return false
	}

	hexPart := s[2:]
	match, _ := regexp.MatchString("^[0-9a-fA-F]+$", hexPart)
	return match
}

// convertToBigInt recursively converts numeric strings within a map or slice to big.Int.
func convertToBigInt(data interface{}) error {
	switch val := data.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if str, ok := v.(string); ok && isNumericString(str) {
				if num, err := strconv.ParseInt(str, 10, 64); err == nil {
					bigInt := big.NewInt(num)
					protoBigInt, err := model.FromBigInt(bigInt)
					if err != nil {
						return err
					}
					val[k] = protoBigInt.Value
				}
			} else if err := convertToBigInt(v); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, item := range val {
			if err := convertToBigInt(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// isNumericString checks if a given string represents a numeric value.
func isNumericString(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// fileExists checks if a file exists at the given path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
