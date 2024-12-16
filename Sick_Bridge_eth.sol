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

//