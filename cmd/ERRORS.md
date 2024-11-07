# ERC-4337 EntryPoint Error Handling Implementation

## Problem Statement
When executing UserOperations through the EntryPoint contract, errors are returned as ABI-encoded data that includes:
1. A 4-byte function selector
2. Encoded parameters specific to each error type
3. These errors need to be properly decoded to provide meaningful feedback to users and debugging capabilities

Key challenges included:
- Handling different error types (FailedOp, UserOperationRevertReason, etc.)
- Properly decoding ABI-encoded data with dynamic types (strings, bytes)
- Managing different error data formats from RPC calls

### 1. Error Type Definition
```go
type EntryPointError struct {
    ErrorType string   // Type of error (e.g., "FailedOp")
    OpIndex   uint64   // Index of failed operation
    Reason    string   // Human-readable error message
    ErrorData []byte   // Additional error data (optional)
}
```

### 2. Error Decoding 

#### a. RPC Error Extraction
- Implements the `rpc.DataError` interface for error data extraction

#### b. ABI Decoding
- Manually constructs ABI types for proper decoding:
  ```go
  uint256Type, _ := abi.NewType("uint256", "", nil)
  stringType, _ := abi.NewType("string", "", nil)
  ```
- Uses `abi.Arguments` for dynamic unpacking of error data
- Supports variable-length data (strings, bytes) properly

#### c. Error Type Recognition
- Identifies error types via 4-byte selectors
- Implements specific handling for each error type:
  ```go
  const (
      FailedOpSelector            = "220266b6"
      UserOperationRevertSelector = "220266b7"
      // ...
  )
  ```
### Example Error Cases

#### 1. AA21 Prefund Error
```go
ErrorType: "FailedOp"
OpIndex: 0
Reason: "AA21 didn't pay prefund"
```

#### 2. Operation Revert with Data
```go
ErrorType: "UserOperationRevertReason"
OpIndex: 1
Reason: "Operation failed"
ErrorData: [0xde 0xad 0xbe 0xef]
```

### Usage Example
```go
tx, err := transaction.HandleOps(&opts)
if err != nil {
    if dataErr, ok := err.(rpc.DataError); ok {
        if epErr, decodeErr := DecodeEntryPointError(dataErr.ErrorData()); decodeErr == nil {
            log.Printf("EntryPoint error: %s", epErr.Error())
        }
    }
}
```