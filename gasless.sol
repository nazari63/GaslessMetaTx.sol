// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaslessMetaTx {
    address public relayer; // واسطه‌ای که کارمزد را می‌پردازد

    event MetaTransactionExecuted(address indexed user, address indexed target, bytes data);

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function executeMetaTransaction(
        address user,
        address target,
        bytes memory data,
        bytes memory signature
    ) public {
        require(msg.sender == relayer, "Only relayer can execute meta-transactions");

        // بازیابی آدرس امضاکننده
        address recovered = recoverSigner(user, target, data, signature);
        require(recovered == user, "Invalid signature");

        // اجرای تراکنش برای کاربر
        (bool success, ) = target.call(data);
        require(success, "Transaction failed");

        emit MetaTransactionExecuted(user, target, data);
    }

    function recoverSigner(
        address user,
        address target,
        bytes memory data,
        bytes memory signature
    ) internal pure returns (address) {
        bytes32 messageHash = keccak256(abi.encodePacked(user, target, data));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}