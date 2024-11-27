package userop

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/blndgs/model"
)

// DebugParseResult contains the parsed cross-chain data along with debug information
type DebugParseResult struct {
	XDataInCallData  bool
	OpType           uint16
	IntentJSONLength int
	IntentJSON       []byte
	LeadingGarbage   []byte // Garbage bytes before IntentJSON
	TrailingGarbage  []byte // Garbage bytes after IntentJSON
	HashListLength   int
	HashList         []model.CrossChainHashListEntry
	Error            error
}

// String implements the Stringer interface for pretty-printing debug results
func (r *DebugParseResult) String() string {
	var b strings.Builder

	// Helper function to format bytes for display
	formatBytes := func(data []byte) string {
		if len(data) == 0 {
			return "none"
		}
		return hex.EncodeToString(data)
	}

	fmt.Fprintf(&b, "=== Cross Chain Data Debug Output ===\n")
	fmt.Fprintf(&b, "OpType: 0x%04x", r.OpType)
	xDataLoc := ""
	if r.XDataInCallData {
		xDataLoc = "xData detected in the CallData field"
	} else {
		xDataLoc = "xData detected in the Signature field"
	}
	if r.OpType == model.CrossChainMarker {
		fmt.Fprintf(&b, " (Valid model.CrossChainMarker) %s", xDataLoc)
	} else {
		fmt.Fprintf(&b, " (Invalid: Expected 0x%04x) %s", model.CrossChainMarker, xDataLoc)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "\nIntentJSON:\n")
	fmt.Fprintf(&b, "  Length: %d bytes\n", r.IntentJSONLength)
	fmt.Fprintf(&b, "  Leading Garbage: %s\n", formatBytes(r.LeadingGarbage))
	fmt.Fprintf(&b, "  Content: %s\n", string(r.IntentJSON))
	fmt.Fprintf(&b, "  Trailing Garbage: %s\n", formatBytes(r.TrailingGarbage))

	fmt.Fprintf(&b, "\nHash List:\n")
	fmt.Fprintf(&b, "  Length: %d entries\n", r.HashListLength)
	for i, entry := range r.HashList {
		if entry.IsPlaceholder {
			fmt.Fprintf(&b, "  [%d] Placeholder (0xFFFF)\n", i)
		} else {
			fmt.Fprintf(&b, "  [%d] Operation Hash: %s\n", i, hex.EncodeToString(entry.OperationHash))
		}
	}

	if r.Error != nil {
		fmt.Fprintf(&b, "\nErrors Detected:\n%v\n", r.Error)
	}

	return b.String()
}

// DebugParseCrossChainData performs detailed parsing of cross-chain data with debugging information
func DebugParseCrossChainData(data []byte, xDataInCallData bool) *DebugParseResult {
	result := &DebugParseResult{
		XDataInCallData: xDataInCallData,
	}

	// Verify minimum length requirements
	if len(data) < model.OpTypeLength+model.IntentJSONLengthSize {
		result.Error = model.ErrMissingCrossChainData
		return result
	}

	// Parse OpType
	result.OpType = binary.BigEndian.Uint16(data[:model.OpTypeLength])
	offset := model.OpTypeLength

	// Parse IntentJSON length
	result.IntentJSONLength = int(binary.BigEndian.Uint16(data[offset : offset+model.IntentJSONLengthSize]))
	offset += model.IntentJSONLengthSize

	// Validate and extract IntentJSON with garbage detection
	if offset+result.IntentJSONLength > len(data) {
		result.Error = errors.New("intent JSON length exceeds available data")
		return result
	}

	// Extract IntentJSON and detect any garbage
	intentJSONStart := offset
	intentJSONEnd := offset + result.IntentJSONLength
	result.IntentJSON = data[intentJSONStart:intentJSONEnd]

	// Check for valid JSON and identify garbage
	validJSON, cleanJSON, leading, trailing := detectJSONBoundaries(result.IntentJSON)
	if !validJSON {
		result.LeadingGarbage = leading
		result.TrailingGarbage = trailing
		result.IntentJSON = cleanJSON
	}

	offset = intentJSONEnd

	// Parse HashList length
	if len(data) <= offset {
		result.Error = errors.New("hash list length is missing")
		return result
	}
	result.HashListLength = int(data[offset])
	offset++

	// Parse HashList entries
	reader := bytes.NewReader(data[offset:])
	hashList, _, err := model.ParseHashListEntries(reader, result.HashListLength)
	if err != nil {
		result.Error = fmt.Errorf("failed to parse hash list: %w", err)
		return result
	}
	result.HashList = hashList

	return result
}

// detectJSONBoundaries attempts to identify valid JSON boundaries and any garbage data
func detectJSONBoundaries(data []byte) (bool, []byte, []byte, []byte) {
	// Find the first '{' character
	start := bytes.IndexByte(data, '{')
	if start == -1 {
		return false, data, data, nil
	}

	// Find the last '}' character
	end := bytes.LastIndexByte(data, '}')
	if end == -1 || end < start {
		return false, data, data, nil
	}

	// Extract the potential JSON content
	jsonContent := data[start : end+1]

	// Validate if it's proper JSON (simplified check)
	bracketCount := 0
	for _, b := range jsonContent {
		if b == '{' {
			bracketCount++
		} else if b == '}' {
			bracketCount--
		}
		if bracketCount < 0 {
			return false, data, data, nil
		}
	}

	if bracketCount != 0 {
		return false, data, data, nil
	}

	leading := data[:start]
	trailing := data[end+1:]

	return true, jsonContent, leading, trailing
}

// NewDebugParser creates a debug parser that can be used to analyze cross-chain data
func NewDebugParser() *DebugParser {
	return &DebugParser{
		verbose: true,
	}
}

// DebugParser provides methods for parsing and analyzing cross-chain data
type DebugParser struct {
	verbose bool
}

// ParseAndDebug parses the provided data and returns both the parsed result and debug information
func (p *DebugParser) ParseAndDebug(data []byte, xDataInCallData bool) (*model.CrossChainData, *DebugParseResult) {
	debugResult := DebugParseCrossChainData(data, xDataInCallData)

	if debugResult.Error != nil {
		return nil, debugResult
	}

	return &model.CrossChainData{
		IntentJSON: debugResult.IntentJSON,
		HashList:   debugResult.HashList,
	}, debugResult
}

// XDataExtractor provides methods to extract XData from UserOperation fields
type XDataExtractor struct {
	parser *DebugParser
}

// NewXDataExtractor creates a new XDataExtractor instance
func NewXDataExtractor() *XDataExtractor {
	return &XDataExtractor{
		parser: NewDebugParser(),
	}
}

// ExtractAndDebug attempts to find and parse XData from a UserOperation
func (x *XDataExtractor) ExtractAndDebug(op *model.UserOperation) (debug *DebugParseResult, err error) {
	// First check callData field
	if len(op.CallData) >= model.OpTypeLength {
		marker := binary.BigEndian.Uint16(op.CallData[:model.OpTypeLength])
		if marker == model.CrossChainMarker {
			_, debug = x.parser.ParseAndDebug(op.CallData, true)
			return
		}
	}

	// Then check signature field
	if len(op.Signature) > model.KernelSignatureLength {
		xDataValue := op.Signature[op.GetSignatureEndIdx():]

		if len(xDataValue) >= model.OpTypeLength {
			marker := binary.BigEndian.Uint16(xDataValue[:model.OpTypeLength])
			if marker == model.CrossChainMarker {
				_, debug = x.parser.ParseAndDebug(xDataValue, false)
				return
			}
		}
	}

	return nil, errors.New("no valid XData found in UserOperation")
}
