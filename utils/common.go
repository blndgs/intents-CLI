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

	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
)

// AddCommonFlags adds common flags to the provided Cobra command.
func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("u", "", "User operation JSON")

	if err := cmd.MarkFlagRequired("u"); err != nil {
		panic(err)
	}
}

// GetUserOps parses the 'userop' JSON string or file provided in the command flags
// and returns a UserOperation object. It panics if the JSON string is empty,
// the file can't be read, or the JSON can't be parsed.
func GetUserOps(cmd *cobra.Command) *model.UserOperation {
	userOpInput, _ := cmd.Flags().GetString("u")

	var userOpJSON string
	if userOpInput == "" {
		panic("user operation JSON is required")
	}
	if userOpInput[0] == '{' {
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

	var userOp model.UserOperation
	err := json.Unmarshal([]byte(userOpJSON), &userOp)
	if err != nil {
		panic(fmt.Errorf("error parsing user operation JSON: %v", err))
	}
	return &userOp
}

// UpdateUserOp sets the nonce value and 4337 default gas limits if they are zero.
func UpdateUserOp(userOp *model.UserOperation, nonce *big.Int) *model.UserOperation {
	zero := big.NewInt(0)

	if userOp.CallGasLimit.Cmp(zero) == 0 {
		userOp.CallGasLimit = big.NewInt(200000)
	}
	if userOp.VerificationGasLimit.Cmp(zero) == 0 {
		userOp.VerificationGasLimit = big.NewInt(65536)
	}
	if userOp.PreVerificationGas.Cmp(zero) == 0 {
		userOp.PreVerificationGas = big.NewInt(65536)
	}

	userOp.Nonce = nonce
	return userOp
}

// PrintSignature prints the signature + hex encoded intent JSON (calldata).
func PrintSignature(userOp *model.UserOperation) {
	fmt.Printf("\nSignature value after solution:\n%s\n",
		hexutil.Encode(userOp.Signature)+hex.EncodeToString(userOp.CallData))
}

// ProcessCallDataUsingBigInt convert the int to ProtoBigInt.
func ProcessCallDataUsingBigInt(jsonData string) (string, error) {
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
