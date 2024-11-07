package cmd

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeEntryPointError(t *testing.T) {
	tests := []struct {
		name     string
		errData  string // Hex string of error data
		expected *EntryPointError
		wantErr  bool
	}{
		{
			name:    "FailedOp - AA21 prefund error",
			errData: "0x220266b600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001741413231206469646e2774207061792070726566756e64000000000000000000",
			expected: &EntryPointError{
				ErrorType: "FailedOp",
				OpIndex:   0,
				Reason:    "AA21 didn't pay prefund",
			},
			wantErr: false,
		},
		{
			name:    "UserOperationRevertReason",
			errData: "0x220266b70000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000104f7065726174696f6e206661696c6564000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004deadbeef00000000000000000000000000000000000000000000000000000000",
			expected: &EntryPointError{
				ErrorType: "UserOperationRevertReason",
				OpIndex:   1,
				Reason:    "Operation failed",
				ErrorData: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			wantErr: false,
		},
		{
			name:    "Invalid hex data",
			errData: "0xZZ",
			wantErr: true,
		},
		{
			name:    "Unknown selector",
			errData: "0xdeadbeef",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataBytes, err := hex.DecodeString(strings.TrimPrefix(tt.errData, "0x"))
			if tt.wantErr && err != nil {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			result, err := DecodeEntryPointError(dataBytes)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected.ErrorType, result.ErrorType)
			assert.Equal(t, tt.expected.OpIndex, result.OpIndex)
			assert.Equal(t, tt.expected.Reason, result.Reason)
			if tt.expected.ErrorData != nil {
				assert.Equal(t, tt.expected.ErrorData, result.ErrorData)
			}
		})
	}
}
