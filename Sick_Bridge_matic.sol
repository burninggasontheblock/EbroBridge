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
