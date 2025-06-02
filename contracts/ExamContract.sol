// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ExamContract {
    // Structure to store exam action logs
    struct ExamAction {
        uint256 examId;      // ID of the exam
        string action;       // Type of action (created, updated, started, submitted, etc.)
        string userId;       // User who performed the action
        string timestamp;    // When the action occurred
        bytes32 dataHash;    // Hash of additional data
    }

    // Array to store all exam actions
    ExamAction[] public examActions;
    
    // Mapping from exam ID to array of action indices for that exam
    mapping(uint256 => uint256[]) public examToActions;
    
    // Mapping from user ID to array of action indices for that user
    mapping(string => uint256[]) public userToActions;
    
    // Contract owner address
    address public owner;
    
    // Event emitted when an action is logged
    event ExamActionLogged(
        uint256 indexed examId,
        string action,
        string userId,
        string timestamp,
        bytes32 dataHash
    );
    
    // Constructor to set the contract owner
    constructor() {
        owner = msg.sender;
    }
    
    // Modifier to restrict certain functions to the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    // Log an exam-related action
    function logExamAction(
        uint256 examId,
        string memory action,
        string memory userId,
        string memory timestamp
    ) public returns (uint256) {
        // Create a hash of the data for verification purposes
        bytes32 dataHash = keccak256(abi.encodePacked(examId, action, userId, timestamp, block.timestamp));
        
        // Create and store the action
        ExamAction memory newAction = ExamAction({
            examId: examId,
            action: action,
            userId: userId,
            timestamp: timestamp,
            dataHash: dataHash
        });
        
        examActions.push(newAction);
        uint256 actionIndex = examActions.length - 1;
        
        // Update mappings
        examToActions[examId].push(actionIndex);
        userToActions[userId].push(actionIndex);
        
        // Emit event
        emit ExamActionLogged(examId, action, userId, timestamp, dataHash);
        
        return actionIndex;
    }
    
    // Get a specific action by index
    function getExamAction(uint256 index) public view returns (
        uint256 examId,
        string memory action,
        string memory userId,
        string memory timestamp,
        bytes32 dataHash
    ) {
        require(index < examActions.length, "Action index out of bounds");
        
        ExamAction memory action = examActions[index];
        return (
            action.examId,
            action.action,
            action.userId,
            action.timestamp,
            action.dataHash
        );
    }
    
    // Get the count of all actions
    function getActionCount() public view returns (uint256) {
        return examActions.length;
    }
    
    // Get all action indices for a specific exam
    function getExamActionIndices(uint256 examId) public view returns (uint256[] memory) {
        return examToActions[examId];
    }
    
    // Get all action indices for a specific user
    function getUserActionIndices(string memory userId) public view returns (uint256[] memory) {
        return userToActions[userId];
    }
    
    // Verify if a given data hash matches the stored hash for an action
    function verifyActionHash(
        uint256 actionIndex,
        uint256 examId,
        string memory action,
        string memory userId,
        string memory timestamp
    ) public view returns (bool) {
        require(actionIndex < examActions.length, "Action index out of bounds");
        
        ExamAction memory storedAction = examActions[actionIndex];
        bytes32 computedHash = keccak256(abi.encodePacked(examId, action, userId, timestamp, block.timestamp));
        
        return storedAction.dataHash == computedHash;
    }
    
    // Transfer ownership of the contract
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner cannot be the zero address");
        owner = newOwner;
    }
}
