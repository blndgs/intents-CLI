package userop

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/blndgs/model"
)

// State represents the state of a UserOperation
type State int

const (
	StateUnsigned State = iota
	StateConventional
	StateIntentUnsolved    // Intent JSON in callData, awaiting solution
	StateSolutionLess      // Intent with empty solution
	StateIntentSolved      // Intent with valid EVM solution
	StateXChainUnsolved    // XData in callData, awaiting solution
	StateXChainInSignature // XData appended to signature
	StateXChainSolved      // XData with valid EVM solution
	StateXChainAggregate   // Special case: Aggregate XChain operation
)

// Color returns ANSI color codes for pretty console printing
func (s State) Color() string {
	return stateColors[s]
}

// String representation of State
func (s State) String() string {
	return [...]string{
		"Unsigned UserOp (invalid or missing signature)",
		"Conventional ERC-4337 UserOp",
		"Intent UserOp awaiting solution: cannot validate signature on-chain. Append the callData value to the signature ECDSA payload for on-chain validation.",
		"Intent UserOp with empty solution: on-chain signature validation is possible.",
		"Intent UserOp with EVM solution: on-chain signature validation is possible.",
		"Cross-chain UserOp awaiting solution: cannot validate signature on-chain. Append the callData value to the signature ECDSA payload for on-chain validation.",
		"Cross-chain UserOp with signature-embedded XData: on-chain signature validation is possible.",
		"Cross-chain UserOp with EVM solution: on-chain signature validation is possible.",
		"Aggregate cross-chain UserOp: cannot validate signature on-chain.",
	}[s]
}

// Color returns ANSI color codes for pretty console printing
var stateColors = map[State]string{
	StateUnsigned:          "\033[31m", // Red
	StateConventional:      "\033[32m", // Green
	StateIntentUnsolved:    "\033[33m", // Yellow
	StateSolutionLess:      "\033[33m", // Yellow
	StateIntentSolved:      "\033[32m", // Green
	StateXChainUnsolved:    "\033[36m", // Cyan
	StateXChainInSignature: "\033[36m", // Cyan
	StateXChainSolved:      "\033[32m", // Green
	StateXChainAggregate:   "\033[35m", // Magenta
}

// DetermineState analyzes a UserOperation to determine its current state
func DetermineState(op *model.UserOperation) State {
	// Check signature validity first
	if !op.HasSignature() {
		return StateUnsigned
	}

	// Check for cross-chain operations
	if op.IsCrossChainOperation() {
		return determineXChainState(op)
	}

	// Check for intent operations
	if op.HasIntent() {
		return determineIntentState(op)
	}

	// Must be conventional
	return StateConventional
}

func HasXDataInCallData(op *model.UserOperation) bool {
	if op == nil || len(op.CallData) == 0 {
		return false
	}
	xData, err := model.ParseCrossChainData(op.CallData)
	if err != nil {
		return false
	}
	return validXData(xData)
}

func HasXDataInSignature(op *model.UserOperation) bool {
	if !op.HasSignature() {
		return false
	}
	xData, err := model.ParseCrossChainData(op.Signature[op.GetSignatureEndIdx():])
	if err != nil {
		return false
	}
	return validXData(xData)
}

func validXData(xData *model.CrossChainData) bool {
	return xData != nil &&
		len(xData.HashList) >= 2 &&
		(len(xData.HashList[0].OperationHash) == 32 ||
			len(xData.HashList[1].OperationHash) == 32) &&
		(xData.HashList[0].IsPlaceholder || xData.HashList[1].IsPlaceholder)
}

func IsAggregate(op *model.UserOperation) bool {
	if !op.IsCrossChainOperation() || op.HasSignatureExact() {
		return false
	}
	cpOp := *op
	if _, err := cpOp.ExtractEmbeddedOp(); err != nil {
		return false
	}
	return true
}

// HasEVMSolution checks if the provided bytes likely represent valid EVM calldata
// through a number of heuristics.
func HasEVMSolution(op *model.UserOperation) bool {
	const (
		// Minimum calldata length: 4 bytes function selector = 8 hex chars
		minCallDataLength = 8
		// Regular expression for valid function selector: 4 bytes in hex
		funcSelectorRegex = `^0x[0-9a-fA-F]{8}`
	)

	if len(op.CallData) < minCallDataLength {
		return false
	}

	// Convert to hex string for regex matching
	hexStr := "0x" + hex.EncodeToString(op.CallData)

	// Check if starts with valid function selector
	matched, _ := regexp.MatchString(funcSelectorRegex, hexStr)
	if !matched {
		return false
	}

	// Additional heuristics:
	// 1. Length must be even (complete bytes)
	if len(hexStr)%2 != 0 {
		return false
	}

	// 2. Must be valid hex throughout
	_, err := hex.DecodeString(hexStr[2:]) // Skip "0x" prefix
	if err != nil {
		return false
	}

	// final check if it's an Intent userOp
	var intentJSON string
	if op.HasIntent() {
		intentJSON, err = op.GetIntentJSON()
		if err != nil {
			// corrupt intent JSON
			return false
		}

		if op.IsCrossChainOperation() {
			return !HasXDataInCallData(op)
		}

		// Same-chain userOp with intent JSON in callData?
		if bytes.Equal(op.CallData, []byte(intentJSON)) {
			return false
		}
	}

	return true
}

func determineXChainState(op *model.UserOperation) State {
	// Check for aggregate operations first
	if IsAggregate(op) {
		return StateXChainAggregate
	}

	xDataAppendedToSignature := HasXDataInSignature(op)

	// Check XData location and solution status
	switch {
	case HasXDataInCallData(op):
		return StateXChainUnsolved
	case xDataAppendedToSignature && solutionLess(op):
		return StateXChainInSignature
	case xDataAppendedToSignature && HasEVMSolution(op):
		return StateXChainSolved
	default:
		// Should never reach here if IsCrossChainOperation was true
		return StateUnsigned
	}
}

func solutionLess(op *model.UserOperation) bool {
	return len(op.CallData) == 0
}

func determineIntentState(op *model.UserOperation) State {
	switch {
	case !HasEVMSolution(op):
		return StateIntentUnsolved
	case len(op.CallData) == 0:
		return StateSolutionLess
	case HasEVMSolution(op):
		return StateIntentSolved
	default:
		return StateIntentUnsolved
	}
}

// ConsoleStyle holds ANSI escape codes for console formatting
type ConsoleStyle struct {
	Color string
	Reset string
}

var (
	styleReset  = "\033[0m"
	styleColors = map[State]ConsoleStyle{
		StateUnsigned: {
			Color: stateColors[StateUnsigned], // Red
			Reset: styleReset,
		},
		StateConventional: {
			Color: stateColors[StateConventional], // Green
			Reset: styleReset,
		},
		StateIntentUnsolved: {
			Color: stateColors[StateIntentUnsolved], // Yellow
			Reset: styleReset,
		},
		StateSolutionLess: {
			Color: stateColors[StateSolutionLess], // Yellow
			Reset: styleReset,
		},
		StateIntentSolved: {
			Color: stateColors[StateIntentSolved], // Green
			Reset: styleReset,
		},
		StateXChainUnsolved: {
			Color: stateColors[StateXChainUnsolved], // Cyan
			Reset: styleReset,
		},
		StateXChainInSignature: {
			Color: stateColors[StateXChainInSignature], // Cyan
			Reset: styleReset,
		},
		StateXChainSolved: {
			Color: stateColors[StateXChainSolved], // Green
			Reset: styleReset,
		},
		StateXChainAggregate: {
			Color: stateColors[StateXChainAggregate], // Magenta
			Reset: styleReset,
		},
	}
)

// Format returns a colored string representation of the state
func (s State) Format() string {
	style := styleColors[s]
	return fmt.Sprintf("%s%s%s", style.Color, s.String(), style.Reset)
}

// FormatWithDetail returns a detailed colored status message
func (s State) FormatWithDetail(extraInfo string) string {
	style := styleColors[s]
	base := fmt.Sprintf("%s%s%s", style.Color, s.String(), style.Reset)
	if extraInfo != "" {
		return fmt.Sprintf("%s (%s)", base, extraInfo)
	}
	return base
}
