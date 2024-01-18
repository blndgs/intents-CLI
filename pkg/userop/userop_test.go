package userop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	"github.com/stretchr/testify/require"
)

// TestSign test sign signature.
func TestSign(t *testing.T) {

	testCases := []struct {
		name           string
		chainID        *big.Int
		entryPointAddr common.Address
		signer         *signer.EOA
		userOp         string
		wantErr        bool
	}{
		{
			name:           "Successful Signing",
			chainID:        big.NewInt(1),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         validPrivateKey(),
			userOp: `{
                "sender": "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47",
                "nonce": "0xf",
                "initCode": "0x",
                "callData": "0x7b22636861696e4964223a38303030312c202273656e646572223a22307830413731393961393666646630323532453039463736353435633145663262653336393246343662222c20226b696e64223a2273776170222c202268617368223a22222c202273656c6c546f6b656e223a22546f6b656e41222c2022627579546f6b656e223a22546f6b656e42222c202273656c6c416d6f756e74223a31302c2022627579416d6f756e74223a352c20227061727469616c6c7946696c6c61626c65223a66616c73652c2022737461747573223a225265636569766564222c2022637265617465644174223a302c202265787069726174696f6e4174223a307d",
                "callGasLimit": "0x0",
                "verificationGasLimit": "0x11170",
                "preVerificationGas": "0x0",
                "maxFeePerGas": "0x0",
                "maxPriorityFeePerGas": "0x0",
                "paymasterAndData": "0x",
                "signature": "0x8e8a12900df61d02ad6907c15315564f55ae38323c82bb44e673a52c6230bc8455a85e6721575f8b139e0d191d24557d46c6670999552a0ad9d3167e25ad3f0b1b"
            }`,
			wantErr: false,
		},
		{
			name:           "Unsuccessful Signing",
			chainID:        big.NewInt(1),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         invalidPrivateKey(),
			userOp: `{
                "sender": "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47",
                "nonce": "0xf",
                "initCode": "0x",
                "callData": "0x7b22636861696e4964223a38303030312c202273656e646572223a22307830413731393961393666646630323532453039463736353435633145663262653336393246343662222c20226b696e64223a2273776170222c202268617368223a22222c202273656c6c546f6b656e223a22546f6b656e41222c2022627579546f6b656e223a22546f6b656e42222c202273656c6c416d6f756e74223a31302c2022627579416d6f756e74223a352c20227061727469616c6c7946696c6c61626c65223a66616c73652c2022737461747573223a225265636569766564222c2022637265617465644174223a302c202265787069726174696f6e4174223a307d",
                "callGasLimit": "0x0",
                "verificationGasLimit": "0x11170",
                "preVerificationGas": "0x0",
                "maxFeePerGas": "0x0",
                "maxPriorityFeePerGas": "0x0",
                "paymasterAndData": "0x",
                "signature": "0x8e8a12900df61d02ad6907c15315564f55ae38323c82bb44e673a52c6230bc8455a85e6721575f8b139e0d191d24557d46c6670999552a0ad9d3167e25ad3f0b1b"
            }`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var userOp model.UserOperation
			err := json.Unmarshal([]byte(tc.userOp), &userOp)
			if err != nil {
				panic(err)
			}
			_, err = userop.Sign(tc.chainID, tc.entryPointAddr, tc.signer, &userOp)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// validPrivateKey is a valid signer keys.
func validPrivateKey() *signer.EOA {
	privateKey, _ := crypto.GenerateKey()
	publicKey := &privateKey.PublicKey
	return &signer.EOA{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// invalidPrivateKey is a invalid signer keys.
func invalidPrivateKey() *signer.EOA {
	return &signer.EOA{
		PrivateKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(), // Using a curve different from the one expected by Ethereum (secp256k1)
				X:     nil,
				Y:     nil,
			},
			D: big.NewInt(0),
		},
	}
}
