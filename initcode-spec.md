# 4337 `initcode` summary spec

Needed if and only if the account is not yet on-chain and needs to be created.

## EoA Owner example

Address:     0xFd4eC985482E1ed2b651293025EDaD889FaC3947
Private key: 0xcddd3f0ae3a7e2024ea73fd74d25e55ebc1849dcbc25eb61d39508d2c5a1a85b

### Value for a non-existing wallet in Ethereum Mainnet

0xFactoryAddress+CalldataOfFactoryCallToCreate4337Account

Complete initcode value example:

`0x42E60c23aCe33c23e0945a07f6e2c1E53843a1d55fbfb9cf000000000000000000000000fd4ec985482e1ed2b651293025edad889fac39470000000000000000000000000000000000000000000000000000000000000000`

20 bytes for the factory address, i.e.

```bash
cast code 0x42E60c23aCe33c23e0945a07f6e2c1E53843a1d5 -r https://virtual.mainnet.rpc.tenderly.co/c4100609-e3ff-441b-a803-5a4e95de809f
```

Note the hex calldata corresponding to the call to create an account using the `createAccount` contract function, i.e.

```bash
cast 4byte-decode 5fbfb9cf000000000000000000000000fd4ec985482e1ed2b651293025edad889fac39470000000000000000000000000000000000000000000000000000000000000000
1) "createAccount(address,uint256)"
0xFd4eC985482E1ed2b651293025EDaD889FaC3947 // owner address
0 // salt
```

Note the owner address, i.e., metamask or EOA address that signs the userOp. In this case it is `0xFd4eC985482E1ed2b651293025EDaD889FaC3947`

### Avoiding the `AA14 initCode must return sender` error

The sender of the userOp creating this account can only be the value returned when calling factory.`getAddress`(owner, salt) which in this example when invoking it in Ethereum Mainnet would be `0x400e8eaefa99f620b2280a2afa47df2a6d016387`