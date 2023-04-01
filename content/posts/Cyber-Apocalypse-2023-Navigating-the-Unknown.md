---
title: "Cyber Apocalypse 2023 Navigating the Unknown"
date: 2023-04-01T12:22:18-07:00
draft: false
---

# README
## Guidelines

The point of this README is to provide some guidance for people who attempt solving a blockchain challenge for the first time.

### Ports

As you have already seen, there are 2 ports provided.

- The one port is the `tcp` port, which is used to retrieve information about connecting to the private chain, such as private key, and the target contract's addresses. You can connect to this one using `netcat`.
- The other port is the `rpc` url. You will need this in order to connect to the private chain.

In order to figure out which one is which, try using `netcat` against both. The one which works is the `tcp` port, while the other one is the `rpc url`.

### Contract Sources

In these challenges, you will meet 2 type of smart contract source files, the `Setup.sol` file and the challenge files.

#### Setup.sol

The `Setup.sol` file contains a single contract, the `Setup`. As the name indicates, inside this contract all the initialization actions are happening. There will typically be 3 functions:

- `constructor()`: It is called automatically once when the contract is deployed and cannot be called again. It contains all the initialization actions of the challenge, like deploying the challenge contracts and any other actions needed.
- `TARGET()`: It returns the address of the challenge contract.
- `isSolved()`: This function contains the final objective of the challenge. It returns `true` if the challenge is solved, `false` otherwise. By reading its source, one is able to figure out what the objective is.

#### Other source files

All the other files provided are the challenge contracts. You will only have to interact with them to solve the challenge. Try analyzing their source carefully and figure out how to break them, following the objective specified in `isSolved` function of the `Setup` contract.

### Interacting with the blockchain

In order to interact wth the smart contracts in the private chain, you will need:

- A private key with some ether. We provide it via the tcp endpoint.
- The target contract's address. We provide both the Setup's and the Target's addresses.
- The rpc url, which can be found using what described earlier.

After having collected all the connection information, then you can either use `web3py` or `web3js` to perform function calls in the smart contracts or any other actions needed. You can find some useful tutorials about both with a little googlin'.
An even handier way is using a tool like `foundry-rs`, which is an easy-to-use cli utility to interact with the blockchain, but there are less examples online than the other alternatives.

# Setup.sol
~~~sol
pragma solidity ^0.8.18;

import {Unknown} from "./Unknown.sol";

contract Setup {
    Unknown public immutable TARGET;

    constructor() {
        TARGET = new Unknown();
    }

    function isSolved() public view returns (bool) {
        return TARGET.updated();
    }
}
~~~
# Unkown.sol
#unkownsol
~~~sol
pragma solidity ^0.8.18;


contract Unknown {
    
    bool public updated;

    function updateSensors(uint256 version) external {
        if (version == 10) {
            updated = true;
        }
    }

}
~~~
## Solution
in #unkownsol it is asking for a 256 int that is equal to 10 after some quick googling.
you should be able to just use the number 10 as the argument for the contract!
~~~python
from web3 import Web3, HTTPProvider

import json

contract_address = '0x9374E8D7ba4c7f14B8000ee51A8903D66BE4b97A'

abi = '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"uint256","name":"version","type":"uint256"}],"name":"updateSensors","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"updated","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]'

  

w3 = Web3(HTTPProvider('http://209.97.134.50:30389/'))

  

public = '0xA2F883ebdbE9c0C50Ce10451cCd166f21e45beaC'

  

private = '0xb500e7f6343b76521935222b5dd3a7e017e96d270941c963da52de98c83cd553'

  

contract = w3.eth.contract(abi=abi, address=contract_address)

  

tx_hash = contract.functions.updateSensors(10).transact()

tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

  

print(tx_receipt)
~~~

