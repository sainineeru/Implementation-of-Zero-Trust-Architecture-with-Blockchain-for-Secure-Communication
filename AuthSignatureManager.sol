// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuthSignatureManager {
    struct SignedMessage {
        address sender;
        bytes signature;
        string message;
        uint256 timestamp;
    }
    
    struct AuthorizedClient {
        address clientAddress;
        uint256 expiryTimestamp;
        bool isActive;
    }

    mapping(bytes32 => SignedMessage) public signedMessages;
    mapping(address => AuthorizedClient) public authorizedClients;
    uint256 public constant AUTH_DURATION = 5 minutes; // Increased from 1 minute

    event MessageSigned(address indexed sender, bytes32 indexed messageHash, bytes signature, string message);
    event ClientAuthorized(address indexed client, uint256 expiryTimestamp);
    event ClientRevoked(address indexed client);
    event SignatureVerified(address indexed sender, bytes32 indexed messageHash, bool isValid);
    
    error InvalidSignature();
    error NotAuthorized();
    error AlreadyAuthorized();
    error NotClient();

    function authorizeClient(bytes memory signature, string memory authMessage) public {
        bytes32 messageHash = getMessageHash(msg.sender, authMessage);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        if (recoverSigner(ethSignedMessageHash, signature) != msg.sender) {
            revert InvalidSignature();
        }
        
        uint256 expiry = block.timestamp + AUTH_DURATION;
        authorizedClients[msg.sender] = AuthorizedClient(msg.sender, expiry, true);
        emit ClientAuthorized(msg.sender, expiry);
    }

    function revokeClient() public {
        AuthorizedClient storage client = authorizedClients[msg.sender];
        if (!client.isActive) {
            revert NotAuthorized();
        }
        client.isActive = false;
        emit ClientRevoked(msg.sender);
    }

    function storeSignature(string memory message, bytes memory signature) public {
        if (!authorizedClients[msg.sender].isActive || 
            block.timestamp >= authorizedClients[msg.sender].expiryTimestamp) {
            revert NotAuthorized();
        }

        bytes32 messageHash = getMessageHash(msg.sender, message);
        if (recoverSigner(getEthSignedMessageHash(messageHash), signature) != msg.sender) {
            revert InvalidSignature();
        }

        signedMessages[messageHash] = SignedMessage(msg.sender, signature, message, block.timestamp);
        emit MessageSigned(msg.sender, messageHash, signature, message);
    }

    function verifySignature(string memory message, bytes memory signature) public returns (bool) {
        bytes32 messageHash = getMessageHash(msg.sender, message);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        SignedMessage memory storedMessage = signedMessages[messageHash];
        if (storedMessage.sender == address(0)) {
            return false;
        }

        address recoveredAddress = recoverSigner(ethSignedMessageHash, signature);
        bool isValid = recoveredAddress == storedMessage.sender;
        emit SignatureVerified(msg.sender, messageHash, isValid);
        return isValid;
    }

    // ... (rest of the functions remain the same: getMessageHash, getEthSignedMessageHash, recoverSigner)

    function getMessageHash(address sender, string memory message) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, message));
    }

    function getEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }

    function recoverSigner(bytes32 ethSignedMessageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");

        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer != address(0), "Invalid signature");

        return signer;
    }
}
