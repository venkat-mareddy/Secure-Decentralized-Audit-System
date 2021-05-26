# Secure-Decentralized-Audit-System

Secure Decentralized Audit System keeps track of the audit information of patients EHR (Electronic Health Record) data. Access to the audit records is constrained. The system tackles the security of data during the creation of accounts, validating and auditing the EHR for patients and audit companies to ensure a secure exchange of records.

## How does secure decentralized audit system meet the goals of security?

1.	The privacy of the records is ensured by AES encryption and RSA public key cryptography. The records are secure achieving confidentiality and Integrity.
2.	Identification and authorization are achieved by the password-based authentication created for the patient and audit company records. No one except the ones having the access can use the system.
3.	All the Authorized entities can query for the records and view the records. This is established by the validation proof and AES decryption of the encoded file.
4.	Immutability for the records in the system is proved by check for consistency of the records in the system. It proved that all the changes are detected and reported at every stage and proper track of the changes is available with proof.
5.	The Decentralization of the system is proved by verifying the Authenticity of the records provided by the trusted server. The audit verification proof reveals the system is in order and records are available.

## Proposed Architecture 
It consists of six components.  

1. Authentication Utility: To provide authentication, we have two dictionaries one for patients and other for audit companies. If there is no existing record created for the patient or audit company, the system provides an opportunity to create their records by capturing the username and the password. The usernames and passwords are stored in dictionaries of patients and  audit companies. If the user fails to authenticate, there will be no access to the facilities the system provides. The authentication is provided at each key operation that system performs.

2. Store Server: This server allows the audit companies to upload the EHR audit records to the server. The audit companies work on adding the records and monitoring them. The files before uploading to the server are of plain text and any one can access the documents and can modify them. To overcome this issue the system requests the patients to upload their documents to the server with the help of the audit companies. During this process, public and private keys are created for every record using RSA. This helps to transfer the files securely. The data in the files in the form of plaintext is encrypted using AES. Even if someone gets the files and cracks the key pair, they cannot understand the information, as it is in encrypted form. All the patient records generate the key pairs the encrypted audit files that are stored with the server.

3. Assign Record: This facility provides the opportunity for the audit companies to create the Merkle tree. The Merkle tree reduces all the complexity and improves the performance while auditing for the changes in the system. It has many proven use cases that helps us to protect the information and get the enough information to distinguish between trusted and untrusted data. Patients have no access to the creation of Merkle tree. Audit companies take care about this. They must authenticate themselves before having the necessary access to the system.

4. Query for the record and display the record if exists: This is the one application of the Merkle tree that helps to validate if the record exists in the Merkle tree using the proof of inclusion. This feature is accessed by the patients as well. The patients can know if their record exists in the system. The patient asks the record to the server if its available. Then server send the record. But how can the patient know its true without any proof. So, the patient asks for the inclusion proof. The hash of the record queried is calculated.

5. Verify Authenticity of record: To ensure the record that exists is not tampered at a point of time and have a proper audit verified for the trust establishment with the server.

6. Consistency of record: The records keep updating with every change done by the patient and the auditing company. The records will never be the same. They keep updating with new versions of files generated. So, it is required to verify if the record is consistent. To verify consistency the audit companies, take two files older and new version of it and verify that all the old version is available in the same order and if any new data is added. At every point, the system keeps track of all the changes and gives the proof for immutability existence in the system for the records.

## Implementation

<img src="screenshots/s1.jpg">
