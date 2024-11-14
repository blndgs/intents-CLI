package utils

import (
	"encoding/json"
	"testing"
)

func TestConvertJSONValuesToBigIntJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name: "JSON with numeric string values",
			input: `{
		"fromAsset": {
			"address": "0x6b175474e89094c44da98b954eedeac495271d0f",
			"amount": {"value": "1000000000000000000"},
			"chainId": {"value": "1"}
		},
		"toAsset": {
			"address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			"amount": {"value": "1000000"},
			"chainId": {"value": "1"}
		}
	}`,
			expected: `{
		"fromAsset": {
			"address": "0x6b175474e89094c44da98b954eedeac495271d0f",
			"amount": {"value": "DeC2s6dkAAA="},
			"chainId": {"value": "AQ=="}
		},
		"toAsset": {
			"address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			"amount": {"value": "D0JA"},
			"chainId": {"value": "AQ=="}
		}
	}`,
			expectError: false,
		},
		{
			name: "Valid complex JSON with multiple values",
			input: `{
				"fromAsset": {
					"address": "USDT",
					"amount": {"value": 1},
					"chainId": {"value": 137}
				},
				"toAsset": {
					"address": "BNB",
					"chainId": {"value": 56}
				}
			}`,
			expected:    `{"fromAsset":{"address":"USDT","amount":{"value":"AQ=="},"chainId":{"value":"iQ=="}},"toAsset":{"address":"BNB","chainId":{"value":"OA=="}}}`,
			expectError: false,
		},
		{
			name: "JSON with very large number",
			input: `{
				"data": {"value": 9007199254740991}
			}`,
			expected:    `{"data":{"value":"H////////w=="}}`, // Corrected expected value
			expectError: false,
		},
		{
			name: "Simple JSON with single value",
			input: `{
				"data": {"value": 42}
			}`,
			expected:    `{"data":{"value":"Kg=="}}`,
			expectError: false,
		},
		{
			name: "JSON with array of values",
			input: `{
				"data": [
					{"value": 1},
					{"value": 2},
					{"value": 3}
				]
			}`,
			expected:    `{"data":[{"value":"AQ=="},{"value":"Ag=="},{"value":"Aw=="}]}`,
			expectError: false,
		},
		{
			name:        "Invalid JSON input",
			input:       `{"bad": json}`,
			expected:    "",
			expectError: true,
		},
		{
			name: "JSON with non-numeric value field",
			input: `{
				"data": {"value": "not a number"}
			}`,
			expected:    `{"data":{"value":"not a number"}}`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute the conversion
			result, err := ConvJSONNum2ProtoValues(tt.input)

			// Check error cases
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// For successful cases, verify the output matches expected
			// First normalize both JSONs to ensure consistent formatting
			var expectedJSON, resultJSON interface{}
			if err := json.Unmarshal([]byte(tt.expected), &expectedJSON); err != nil {
				t.Fatalf("Failed to parse expected JSON: %v", err)
			}
			if err := json.Unmarshal([]byte(result), &resultJSON); err != nil {
				t.Fatalf("Failed to parse result JSON: %v", err)
			}

			// Re-marshal both JSONs to normalize formatting
			expectedBytes, _ := json.Marshal(expectedJSON)
			resultBytes, _ := json.Marshal(resultJSON)

			if string(expectedBytes) != string(resultBytes) {
				t.Errorf("Expected %s but got %s", string(expectedBytes), string(resultBytes))
			}
		})
	}
}

// TestConvertJSONValuesToBigIntJSONEdgeCases tests edge cases and boundary conditions
func TestConvertJSONValuesToBigIntJSONEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "Empty JSON object",
			input:       `{}`,
			expectError: false,
		},
		{
			name:        "Empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "Null input",
			input:       "null",
			expectError: false,
		},
		{
			name:        "Deeply nested structure",
			input:       `{"a":{"b":{"c":{"d":{"e":{"value":42}}}}}}`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ConvJSONNum2ProtoValues(tt.input)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Log(out)
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
