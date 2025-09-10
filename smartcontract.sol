// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SecurePHR {
    struct PHR {
        string name;
        string age;
        string diseaseEncrypted;
        string diagnosisEncrypted;
        string labResultsEncrypted;
        address owner;
        uint timestamp;
        bytes32 diseaseHash;
        bytes32 diagnosisHash;
        bytes32 labResultsHash;
    }

    mapping(string => PHR) private phrRecords;
    mapping(string => bool) private classifiedSensitive;

    event PHRStored(string id, address indexed owner, uint timestamp);
    event AccessAttempt(address indexed user, string indexed id, bool granted);
    event QBSAICategorized(string indexed id, string field, bool isSensitive);
    event Encrypted(string indexed id, bytes32 diseaseHash, bytes32 diagnosisHash, bytes32 labResultsHash);
    event Decrypted(string indexed id, string disease, string diagnosis, string labResults);

    modifier validPHRId(string memory id) {
        require(bytes(id).length > 0, "Empty PHR ID");
        _;
    }

    // Store PHR data (no access restriction)
    function storePHR(
        string memory id,
        string memory name,
        string memory age,
        string memory diseaseEncrypted,
        string memory diagnosisEncrypted,
        string memory labResultsEncrypted
    ) public validPHRId(id) {
        // Allow only creator to update existing record
        if (phrRecords[id].owner != address(0)) {
            require(phrRecords[id].owner == msg.sender, "Only owner can update PHR");
        }

        // Mark fields as sensitive
        classifiedSensitive[string(abi.encodePacked(id, "_disease"))] = true;
        classifiedSensitive[string(abi.encodePacked(id, "_diagnosis"))] = true;
        classifiedSensitive[string(abi.encodePacked(id, "_labResults"))] = true;

        emit QBSAICategorized(id, "disease", true);
        emit QBSAICategorized(id, "diagnosis", true);
        emit QBSAICategorized(id, "labResults", true);

        phrRecords[id] = PHR({
            name: name,
            age: age,
            diseaseEncrypted: diseaseEncrypted,
            diagnosisEncrypted: diagnosisEncrypted,
            labResultsEncrypted: labResultsEncrypted,
            owner: msg.sender,
            timestamp: block.timestamp,
            diseaseHash: 0,
            diagnosisHash: 0,
            labResultsHash: 0
        });

        emit PHRStored(id, msg.sender, block.timestamp);
    }

    // Encrypt sensitive fields by hashing them
    function encryptSensitiveById(string memory id) public validPHRId(id) {
        require(phrRecords[id].owner == msg.sender, "Only owner can encrypt PHR");
        PHR storage record = phrRecords[id];
        record.diseaseHash = keccak256(abi.encodePacked(record.diseaseEncrypted));
        record.diagnosisHash = keccak256(abi.encodePacked(record.diagnosisEncrypted));
        record.labResultsHash = keccak256(abi.encodePacked(record.labResultsEncrypted));

        emit Encrypted(id, record.diseaseHash, record.diagnosisHash, record.labResultsHash);
    }

    // Decrypt sensitive fields (just emit the stored encrypted values for this example)
    function decryptSensitiveById(string memory id) public validPHRId(id) {
        require(phrRecords[id].owner == msg.sender, "Only owner can decrypt PHR");
        PHR memory record = phrRecords[id];

        emit Decrypted(id, record.diseaseEncrypted, record.diagnosisEncrypted, record.labResultsEncrypted);
    }

    // View PHR if owner
    function getPHR(string memory id) public view validPHRId(id) returns (
        string memory name,
        string memory age,
        string memory diseaseEncrypted,
        string memory diagnosisEncrypted,
        string memory labResultsEncrypted,
        uint timestamp
    ) {
        require(phrRecords[id].owner != address(0), "PHR does not exist");
        require(msg.sender == phrRecords[id].owner, "Access denied");

        PHR memory record = phrRecords[id];
        return (
            record.name,
            record.age,
            record.diseaseEncrypted,
            record.diagnosisEncrypted,
            record.labResultsEncrypted,
            record.timestamp
        );
    }

    function verifyAccess(string memory id) public view validPHRId(id) returns (bool) {
        if (phrRecords[id].owner == address(0)) return false;
        return msg.sender == phrRecords[id].owner;
    }

    function checkAndLogAccess(string memory id) public validPHRId(id) returns (bool) {
        bool access = (phrRecords[id].owner != address(0)) && (msg.sender == phrRecords[id].owner);
        emit AccessAttempt(msg.sender, id, access);
        return access;
    }

    function isFieldSensitive(string memory id, string memory field) public view returns (bool) {
        return classifiedSensitive[string(abi.encodePacked(id, "_", field))];
    }
} 