# intents-cli

A CLI tool for signing and executing user operations with advanced cross-chain support.

## Features

- Sign single or multiple UserOperations
- Support for cross-chain and aggregated UserOperations
- Multi-chain configuration via chain ID or moniker
- Generate UserOperation hashes and aggregate cross-chain hashes
- Extract embedded UserOperations from aggregates
- Recover signers from UserOperation signatures
- Output EntryPoint handleOps callData
- Support for major EVM chains (ETH, BSC, Polygon)

## Building and Setup

### Building the Application

```sh
make build
```

## Configuration

Set up your .env file with required configurations. Checkout `.env.example` for the reference. Example:

```env
# EOA Signer
SIGNER_PRIVATE_KEY=<your-private-key>

# Chain RPC Endpoints
ETH_NODE_URL_POLYGON_DEFAULT=https://polygon.rpc...  # Chain ID: 137
ETH_NODE_URL_BSC=https://bsc.rpc...                  # Chain ID: 56
ETH_NODE_URL_ETH=https://eth.rpc...                  # Chain ID: 1
ETH_NODE_URL_VBSC890=https://virtual.bsc.rpc...      # Virtual Chain ID: 890
ETH_NODE_URL_VETH888=https://virtual.eth.rpc...      # Virtual Chain ID: 888

# Bundler Configuration
BUNDLER_URL=https://bundler.network

# EntryPoint Contract
ENTRYPOINT_ADDR=0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
```

## Commands
### Available Commands

- sign: Sign single or cross-chain UserOperations
- send: Submit UserOp to EntryPoint handleOps
- sign-send: Sign and submit in one command
- hash: Generate UserOp hash
- recover: Recover signer from UserOp signature
- extract: Extract embedded UserOp from aggregate
- on-chain: Direct submission to EntryPoint

### Command Flags

- --c: Chain selector by ID or moniker (e.g., "137", "bsc", "eth")
- --s: Signature hex string for recovery
- --h: UserOp hash hex string
- --u: UserOperation JSON string or file path

### Chain Configuration

The tool supports multiple chains through environment variables and command-line flags. Chain selection is handled via 
the `--c` flag.
Note the common prefix `ETH_NODE_URL_` followed by the chain moniker in uppercase. 
The moniker is used as the environment variable name or the chain ID for the `--c` flag.
Any environment variable with the `ETH_NODE_URL_` + the "DEFAULT" moniker is selected as the first default chain configuration.

#### Example Chain Moniker and IDs

| Chain    | Chain ID | Chain Moniker (`--c` flag) | Environment Variable |
|----------|----------|----------------------------|---------------------|
| Polygon  | 137      | [default] - no flag needed | `ETH_NODE_URL_POLYGON_DEFAULT` |
| BSC      | 56       | `bsc`  or 56               | `ETH_NODE_URL_BSC` |
| Ethereum | 1        | `eth`  or 1                | `ETH_NODE_URL_ETH` |

## Usage

### Basic Usage

```bash
go run main.go sign --u '<userOperation>'
```

#### Using JSON Input String

To run the application with a JSON input string, use:

```sh
intents-cli --u 'USER_OP_JSON'
```

Note the userOp nonce value is automatically generated by the CLI.

#### Using JSON File

Alternatively, you can use a JSON file as input:

```sh
intents-cli [command] --u ./sample.json
```

## Input Format

### Single UserOperation

```json
{
  "sender": "0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5",
  "nonce": "0x1",
  "initCode": "0x",
  "callData": "...",
  "callGasLimit": "0xc3500",
  "verificationGasLimit": "0x996a0",
  "preVerificationGas": "0x99000",
  "maxFeePerGas": "0x0",
  "maxPriorityFeePerGas": "0x0",
  "paymasterAndData": "0x",
  "signature": "0x"
}
```

### Multiple UserOperations

```json
[
  {
    "sender": "0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5",
    "nonce": "0x1",
    ...
  },
  {
    "sender": "0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5",
    "nonce": "0x2",
    ...
  }
]
```

#### Usage Examples:
```bash
# Polygon (default chain) - no --c flag needed
go run main.go sign --u '<userOperation>'

# Polygon (default) for the first userOperation, BSC for the second user operation
go run main.go sign --c bsc --u '[<userOperation1>, <userOperation2>]]'

# Ethereum
go run main.go sign --c eth --u '<userOperation>'

# Specific chain by ID: Ethereum mainnet
intents-cli sign --c 1 --u '<userOp>'

# Cross-chain operation (Polygon -> BSC)
intents-cli sign --c bsc --u '[<userOp1>, <userOp2>]'
```

#### Important Notes:
- Polygon in this example configuration is the default chain and doesn't require the `--c` flag
- Chain monikers are case-sensitive
- Each chain requires its corresponding RPC URL in the `.env` file


### Cross-Chain Operations

#### Using the `--c` Flag

The `--c` flag specifies which chain configuration to use starting with the second userOp because the default maps to 
the first. This applies for cross-chain transactions where the UserOperation might interact with multiple chains.

```bash
# For BSC operations
go run main.go sign --c bsc --u '<userOperation>'

# For Polygon operations
go run main.go sign --c polygon --u '<userOperation>'
```

#### Cross-Chain UserOperation Structure

When creating a UserOperation that involves cross-chain interactions, the `callData` field should specify the source and destination chain IDs:

```json
{
  "fromAsset": {
    "address": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "amount": {"value": "I4byb8EAAA=="},
    "chainId": {"value": "iQ=="} // Base64 encoded chain ID
  },
  "toStake": {
    "address": "0x1adB950d8bB3dA4bE104211D5AB038628e477fE6",
    "amount": {"value": "D0JA"},
    "chainId": {"value": "OA=="} // Base64 encoded chain ID
  }
}
```

#### Multi-Chain userOp Example

```bash
go run main.go sign --c bsc --u '[
  {
    "sender": "0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5",
    "nonce": "0x1",
    "callData": {
      "fromAsset": {
        "chainId": {"value": "56"}, # BSC
        ...
      },
      "toStake": {
        "chainId": {"value": "137"}, # Polygon
        ...
      }
    },
    ...
  }
]'
```

JSON accepted also in its human readable format:
```json
{
  "fromAsset": {
    "address": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "amount": {"value": "1000000000000000000"},
    "chainId": {"value": "137"}
  },
  "toStake": {
    "address": "0x1adB950d8bB3dA4bE104211D5AB038628e477fE6",
    "amount": {"value": "1000000"},
    "chainId": {"value": "56"}
  }
}
```

## Advanced Operations
### Recover Signer
#### Recover the signing address from a UserOperation:
```
intents-cli recover --c 137 --u '<userOp>'
```
Example output:
```
=== UserOperation Status ===
Cross-chain UserOp awaiting solution: (Chain ID: 137)
Signature is valid for recovered: 0x1E13289c...
```
### Extract Embedded UserOp
#### Extract an embedded UserOperation from an aggregate:
```
intents-cli extract --u '<aggregateUserOp>'
```
### Example output:
```
Source userOp:
[Original UserOp details]

===================== Extracted userOp =====================>
[Extracted UserOp details]
```

## Sample UserOperation Format
### userOp
```json
{
  "sender": "0x388b635c58Ee82a6748A2033f4520E6976064CE3",
  "nonce": "0x1",
  "initCode": "0x",
  "callData": "0x",
  "callGasLimit": "0xc3500",
  "verificationGasLimit": "0x996a0",
  "preVerificationGas": "0x99000",
  "maxFeePerGas": "0x0",
  "maxPriorityFeePerGas": "0x0",
  "paymasterAndData": "0x",
  "signature": "0x"
}
```



## Examples
1 - Sign a blank userOp without initcode or calldata values:

```shell
intents-cli sign --u '{
        "sender":"0x1af5Dc71CE5F2e3aE90bf2b3ECD0a3498f981ab3",
        "nonce":"0x0",
        "initCode":"0x",
        "callData":"",
        "callGasLimit":"0xc3500",
        "verificationGasLimit":"0x996a0",
        "preVerificationGas":"0x99000",
        "maxFeePerGas":"0x0",
        "maxPriorityFeePerGas":"0x0",
        "paymasterAndData":"0x",
        "signature":"0x"
}'
```

2 - Sign a userOp with initcode and calldata values:

Note here the EIP-4337 initcode spec for creating a new account: [initcode-spec.md](./initcode-spec.md)

```shell
intents-cli sign --u '{
        "sender":"0x1af5Dc71CE5F2e3aE90bf2b3ECD0a3498f981ab3",
        "nonce":"0x0",
        "initCode":"0x42E60c23aCe33c23e0945a07f6e2c1E53843a1d55fbfb9cf000000000000000000000000fd4ec985482e1ed2b651293025EDaD889FaC3947",
        "callData":"0x5fbfb9cf000000000000000000000000fd4ec985482e1ed2b651293025EDaD889FaC394700",
        "callGasLimit":"0xc3500",
        "verificationGasLimit":"0x996a0",
        "preVerificationGas":"0x99000",
        "maxFeePerGas":"0x0",
        "maxPriorityFeePerGas":"0x0",
        "paymasterAndData":"0x",
        "signature":"0x"
}'
```
3 - Sign multiple userOps with different chain monikers:

```shell

Here's a full example of signing multiple UserOperations for cross-chain transactions:

```shell
go run main.go sign --c bsc --u '[
  {
    "sender":"0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5",
    "nonce":"0x1",
    "initCode":"0x",
    "callData":"{\"fromAsset\":{\"address\":\"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"amount\":{\"value\":\"I4byb8EAAA==\"},\"chainId\":{\"value\":\"iQ==\"}},\"toStake\":{\"address\":\"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6\",\"amount\":{\"value\":\"D0JA\"},\"chainId\":{\"value\":\"OA==\"}}}",
    "callGasLimit":"0xc3500",
    "verificationGasLimit":"0x996a0",
    "preVerificationGas":"0x99000",
    "maxFeePerGas":"0x0",
    "maxPriorityFeePerGas":"0x0",
    "paymasterAndData":"0x",
    "signature":"0x"
  },
  {
    "sender":"0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5",
    "nonce":"0x1",
    "initCode":"0x",
    "callData":"{\"fromAsset\":{\"address\":\"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"amount\":{\"value\":\"I4byb8EAAA==\"},\"chainId\":{\"value\":\"iQ==\"}},\"toStake\":{\"address\":\"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6\",\"amount\":{\"value\":\"D0JA\"},\"chainId\":{\"value\":\"OA==\"}}}",
    "callGasLimit":"0xc3500",
    "verificationGasLimit":"0x996a0",
    "preVerificationGas":"0x99000",
    "maxFeePerGas":"0x0",
    "maxPriorityFeePerGas":"0x0",
    "paymasterAndData":"0x",
    "signature":"0x"
  }
]'
```

4 - Recover a signature from an aggregate userOp:
```shell
go run main.go recover --c 137 --u '{"sender":"0x388b635c58Ee82a6748A203
3f4520E6976064CE3","nonce":"0xd","initCode":"0x","callData":"0xffff00fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d024e12f42aa10064ae18bc235532746765b0df7f5fd424538914a84f432bd3589cffff","callGasLimit":"0xc3500","verificationGasLimit":"0x996a0","preVerificationGas":"0x99000","maxFeePerGas":"0x0","maxPriorityFeePerGas":"0x0","paymasterAndData":"0x","signature":"0x06447f841fbeeee3f093f1a079f7a0c05873aa3d0121e7eb3f9a6c65956494d0177ac5dc8d6624478cd05e84bf6a8f514be07d9cbd734f6cc1920ab585c6d4091b01000000000000000000000000000000000000000000000000000000000000000000000000000c3500000000000009900000000000000996a002ffffec15f3b5bbcee795d9dd96fcb09bdd119ec8e178b521c5f918a8120165122dc6"}'
Recovering for the provided chain: 137
Other UserOp's hash: 0x4e12f42aa10064ae18bc235532746765b0df7f5fd424538914a84f432bd3589c
UserOp hash: 0xec15f3b5bbcee795d9dd96fcb09bdd119ec8e178b521c5f918a8120165122dc6
XChain hash from the userOp callData field: 0x228d04b77ef0719d8899742eb3ffe4f8b45cca6f64b5d32186f0036c7f62caff
Signature is valid for recovered: 0x1E13289c8d59947b5959E74415F68Ef56805ffeC

=== UserOperation Status ===
Aggregate cross-chain UserOp: cannot validate signature on-chain. (Chain ID: 137).  Append the callData value to the signature ECDSA payload for on-chain validation.
```

5 - Recover a signature from a cross-chain userOp:
```shell
go run main.go recover --c 56 --u '{"sender":"0x388b635c58Ee82a6748A2033f4520E6976064CE3","nonce":"0x0","initCode":"0x","callData":"0xffff00fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d02ffffec15f3b5bbcee795d9dd96fcb09bdd119ec8e178b521c5f918a8120165122dc6","callGasLimit":"0xc3500","verificationGasLimit":"0x996a0","preVerificationGas":"0x99000","maxFeePerGas":"0x0","maxPriorityFeePerGas":"0x0","paymasterAndData":"0x","signature":"0x06447f841fbeeee3f093f1a079f7a0c05873aa3d0121e7eb3f9a6c65956494d0177ac5dc8d6624478cd05e84bf6a8f514be07d9cbd734f6cc1920ab585c6d4091b"}'
Recovering for the provided chain: 56
Parsed xData in the calldata field.
UserOp hash: 0x4e12f42aa10064ae18bc235532746765b0df7f5fd424538914a84f432bd3589c
Other UserOp's hash: 0xec15f3b5bbcee795d9dd96fcb09bdd119ec8e178b521c5f918a8120165122dc6
XChain hash from the userOp signature field: 0x228d04b77ef0719d8899742eb3ffe4f8b45cca6f64b5d32186f0036c7f62caff
Signature is valid for recovered: 0x1E13289c8d59947b5959E74415F68Ef56805ffeC

=== UserOperation Status ===
Cross-chain UserOp awaiting solution: cannot validate signature on-chain. (Chain ID: 56). Append the callData value to the signature ECDSA payload for on-chain validation. 
``` 

Example output:
```
Signer private key: 0x************************************************
Public key: 685437284bbad2533f115de951f0f0deb803b9a4dddcfe06894dfd72defe10b53117abdb81aab2bb1d695bc0c8688a2153639718b3c410b70c8c1de3758ac49e
Address: 0xE0ea66C1d0d0bbf67ab8Bf85731D9011983C9E26
Entrypoint Address: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
Node moniker: vbsc890 url: https://virtual.binance.rpc.tenderly.co/*********************
Node moniker: eth url: https://mainnet.gateway.tenderly.co/*************
Node moniker: default url: https://polygon.gateway.tenderly.co/*************
Node moniker: bsc url: https://site1.moralis-nodes.com/bsc/***********************

UserOp hash: 0x54cf0aa22319b719a7c4d9dd750528e2929de0890b8eaed2804ea93e218ceba2 for default:137 chain
UserOp hash: 0x2bc16073c342558aeaa44ba6a14741350c7c1506eb3297348fd41e5e72b49759 for bsc:56 chain
Aggregate xChain hash: 0x8e020d460e7db7efac80f379071da10f43fabd8f714ca68df7ce4d86908c5591

Entrypoint handleOps callData: 
0x1fad948c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000008ee0051fdb9bb3e3ac94faa30d31895fa9a3adc5000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000008ee0051fdb9bb3e3ac94faa30d31895fa9a3adc500000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000c350000000000000000000000000000000000000000000000000000000000000996a000000000000000000000000000000000000000000000000000000000000990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000002c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000


Signed userOp 0:
UserOperation{
  Sender: 0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5
  Nonce: 0x4, 4
  InitCode: 0x
  CallData: {"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","amount":{"value":"I4byb8EAAA=="},"chainId":{"value":"iQ=="}},"toStake":{"address":"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6","amount":{"value":"D0JA"},"chainId":{"value":"OA=="}}}
  CallGasLimit: 0xc3500, 800000
  VerificationGasLimit: 0x996a0, 628384
  PreVerificationGas: 0x99000, 626688
  MaxFeePerGas: 0x0, 0
  MaxPriorityFeePerGas: 0x0, 0
  PaymasterAndData: 0x
  Signature: 0xa0f4124dfe7a1c065b17b84ed20e3e1361d0da488a21b8d80b324aed7c14dd6e4558b14a3762feef01a7164cd9cbca389d1756ccd45eaf003f52bcac252158fe1cffff00fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d022bc16073c342558aeaa44ba6a14741350c7c1506eb3297348fd41e5e72b49759ffff
}
Signed UserOp in JSON: {"sender":"0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5","nonce":"0x4","initCode":"0x","callData":"0x","callGasLimit":"0xc3500","verificationGasLimit":"0x996a0","preVerificationGas":"0x99000","maxFeePerGas":"0x0","maxPriorityFeePerGas":"0x0","paymasterAndData":"0x","signature":"0xa0f4124dfe7a1c065b17b84ed20e3e1361d0da488a21b8d80b324aed7c14dd6e4558b14a3762feef01a7164cd9cbca389d1756ccd45eaf003f52bcac252158fe1cffff00fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d022bc16073c342558aeaa44ba6a14741350c7c1506eb3297348fd41e5e72b49759ffff"}

Signed userOp 1:
UserOperation{
  Sender: 0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5
  Nonce: 0x1, 1
  InitCode: 0x
  CallData: {"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","amount":{"value":"I4byb8EAAA=="},"chainId":{"value":"iQ=="}},"toStake":{"address":"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6","amount":{"value":"D0JA"},"chainId":{"value":"OA=="}}}
  CallGasLimit: 0xc3500, 800000
  VerificationGasLimit: 0x996a0, 628384
  PreVerificationGas: 0x99000, 626688
  MaxFeePerGas: 0x0, 0
  MaxPriorityFeePerGas: 0x0, 0
  PaymasterAndData: 0x
  Signature: 0xa0f4124dfe7a1c065b17b84ed20e3e1361d0da488a21b8d80b324aed7c14dd6e4558b14a3762feef01a7164cd9cbca389d1756ccd45eaf003f52bcac252158fe1cffff00fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d02ffff54cf0aa22319b719a7c4d9dd750528e2929de0890b8eaed2804ea93e218ceba2
}
Signed UserOp in JSON: {"sender":"0x8Ee0051fDb9Bb3e3Ac94faa30d31895FA9A3ADC5","nonce":"0x1","initCode":"0x","callData":"0x","callGasLimit":"0xc3500","verificationGasLimit":"0x996a0","preVerificationGas":"0x99000","maxFeePerGas":"0x0","maxPriorityFeePerGas":"0x0","paymasterAndData":"0x","signature":"0xa0f4124dfe7a1c065b17b84ed20e3e1361d0da488a21b8d80b324aed7c14dd6e4558b14a3762feef01a7164cd9cbca389d1756ccd45eaf003f52bcac252158fe1cffff00fb7b2266726f6d4173736574223a7b2261646472657373223a22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22616d6f756e74223a7b2276616c7565223a22493462796238454141413d3d227d2c22636861696e4964223a7b2276616c7565223a2269513d3d227d7d2c22746f5374616b65223a7b2261646472657373223a22307831616442393530643862423364413462453130343231314435414230333836323865343737664536222c22616d6f756e74223a7b2276616c7565223a2244304a41227d2c22636861696e4964223a7b2276616c7565223a224f413d3d227d7d7d02ffff54cf0aa22319b719a7c4d9dd750528e2929de0890b8eaed2804ea93e218ceba2"}
```

### Cleaning Up

To clean up the binaries:

```sh
make clean
```

### Running Tests

Run unit and race tests using:

```sh
make run-tests
```
```
make test-unit
```

```
make test-race
```

### Linting
```sh
make lint
```