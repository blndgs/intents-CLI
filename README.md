# intents-sdk

Intents SDK is a CLI tool designed for signing and sending user operations.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Building the Application

To build the application, run:

```sh
make build
```

### Configuration

Before running intents-sdk, ensure that your `.env` file is set up correctly with the necessary configurations like `ETH_NODE_URL`, `SIGNER_PRIVATE_KEY`, etc.
Checkout `.env.example` for the reference.

### Running the Application

#### Using JSON Input String

To run the application with a JSON input string, use:

```sh
intents-sdk --userop 'USER_OP_JSON'
```

#### Using JSON File

Alternatively, you can use a JSON file as input:

```sh
intents-sdk [command] --userop ./sample.json
```

### Available Commands

- `sign`: Sign  a userOp.
- `send`: Send a userOp.
- `sign-send` : Sign and send a userOp.

### Available Flags

- `--userop`: User operation JSON as string or path to a JSON file.
- `--zerogas`: Use zero gas mode, default is `false`.

### Cleaning Up

To clean up the binaries:

```sh
make clean
```

### Running Tests

Run unit and race tests using:

```sh
make test-unit
make test-race
```
