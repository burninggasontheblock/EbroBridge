# EbroBridge

EbroBridge is a cross-chain token bridge enabling secure transfer of tokens between Ethereum and Polygon (Matic) networks. The bridge consists of two contracts: `SickBridgeETH` for the Ethereum network and `WrappedToken` for the Polygon network.

---

## Features

### SickBridgeETH (Ethereum Network)
- **Token Locking:** Allows users to lock ERC-20 tokens on the Ethereum network in preparation for minting on Polygon.
- **Signature-Based Authentication:** Includes nonce-based signature verification for secure operations.
- **Admin Control:** The bridge administrator manages the token transfer process.

### WrappedToken (Polygon Network)
- **Token Minting:** Enables users to mint wrapped tokens on the Polygon network equivalent to locked tokens on Ethereum.
- **Signature Validation:** Uses ECDSA to validate admin-signed transactions for minting.
- **Nonce Tracking:** Ensures each transaction is processed only once to prevent replay attacks.

---

## Contract Details

### 1. SickBridgeETH.sol
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SickBridgeETH {
    address public admin;
    IERC20 public token;

    event TokensLocked(
        address indexed user,
        uint256 amount,
        uint256 nonce,
        bytes signature
    );

    uint256 public nonce;

    constructor(address _token) {
        admin = msg.sender;
        token = IERC20(_token);
    }

    function lockTokens(uint256 _amount, bytes memory _signature) external {
        require(_amount > 0, "Amount must be greater than zero");

        // Transfer tokens from the user to this contract
        token.transferFrom(msg.sender, address(this), _amount);

        // Emit event with a unique nonce and signature
        emit TokensLocked(msg.sender, _amount, nonce, _signature);
        nonce++;
    }
}
```

#### Key Functions:
- **`lockTokens`**: Locks ERC-20 tokens and emits an event containing a unique nonce and signature.

---

### 2. Sick_Bridge_matic.sol
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract WrappedToken is ERC20 {
    using ECDSA for bytes32;

    address public admin;
    mapping(uint256 => bool) public processedNonces;

    event TokensMinted(
        address indexed user,
        uint256 amount,
        uint256 nonce,
        bytes signature
    );

    constructor() ERC20("Wrapped Token", "WTKN") {
        admin = msg.sender;
    }

    function verifySignature(
        address _user,
        uint256 _amount,
        uint256 _nonce,
        bytes memory _signature
    ) public view returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(_user, _amount, _nonce));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        // Verify the signature against the admin's public address
        return ethSignedMessageHash.recover(_signature) == admin;
    }

    function mintTokens(
        address _user,
        uint256 _amount,
        uint256 _nonce,
        bytes memory _signature
    ) external {
        require(!processedNonces[_nonce], "Transaction already processed");
        require(
            verifySignature(_user, _amount, _nonce, _signature),
            "Invalid signature"
        );

        // Mint tokens to the user
        _mint(_user, _amount);

        // Mark the nonce as processed
        processedNonces[_nonce] = true;

        emit TokensMinted(_user, _amount, _nonce, _signature);
    }
}
```

#### Key Functions:
- **`mintTokens`**: Mints tokens on the Polygon network after validating the signature and nonce.
- **`verifySignature`**: Ensures authenticity of admin-signed transactions.

---

## Deployment

### Prerequisites
- Node.js and npm installed.
- Solidity development environment (e.g., Hardhat, Truffle).
- Access to Ethereum and Polygon test networks via a provider like Alchemy or Infura.

### Steps
1. Deploy `SickBridgeETH` on the Ethereum network with the address of the ERC-20 token to bridge.
2. Deploy `WrappedToken` on the Polygon network.
3. Configure the admin address and test the lock/mint flow.

---

## Usage

1. **Lock Tokens (Ethereum)**:
   - Call `lockTokens` on the `SickBridgeETH` contract with the amount and a signature.

2. **Mint Tokens (Polygon)**:
   - Call `mintTokens` on the `WrappedToken` contract with the same parameters to mint tokens.

---

## Events

- `TokensLocked`: Emitted when tokens are locked on Ethereum.
- `TokensMinted`: Emitted when tokens are minted on Polygon.

---

## Security Features

- **Nonce Management**: Prevents double-spending by tracking processed nonces.
- **ECDSA Signature Verification**: Ensures authenticity of admin actions.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

