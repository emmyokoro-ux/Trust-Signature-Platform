# Secure Document Authentication & Multi-Party Signature Registry

An enterprise-grade blockchain smart contract built on Stacks for managing cryptographically-secured digital document signatures with comprehensive verification, multi-party authentication, lifecycle management, and immutable audit trails.

## Overview

This smart contract provides a robust system for digital document authentication that enables multiple parties to cryptographically sign documents while maintaining complete transparency and security through blockchain technology. Perfect for legal contracts, business agreements, and official documentation that requires tamper-proof verification.

## Key Features

### **Cryptographic Security**
- secp256k1 digital signature verification
- SHA-256 hash-based document identification
- Composite message hashing for enhanced security
- Public key registration and validation

### **Document Management**
- Immutable document registration with metadata
- Document lifecycle management (active/revoked states)
- Creator-controlled access permissions
- Comprehensive audit trails

### **Multi-Party Signatures**
- Support for multiple signatories per document
- Signature verification and authentication
- Contextual messaging for each signature
- Batch verification for up to 10 parties

### **Analytics & Reporting**
- Real-time signature count tracking
- System-wide document statistics
- Individual signature status monitoring
- Complete verification history

## Core Data Structures

### Document Registry
Each registered document contains:
- **Document Hash**: Unique 32-byte identifier
- **Creator**: Original document owner principal
- **Metadata**: Title and description (UTF-8 encoded)
- **Timestamps**: Creation time on blockchain
- **Status**: Active or revoked lifecycle state
- **Signature Count**: Total verified signatures

### Signature Records
Each signature includes:
- **Digital Proof**: 65-byte cryptographic signature
- **Timestamp**: Signature creation time
- **Context**: Optional message (256 characters)
- **Verification Status**: Valid/invalid state

### User Registry
Registered users have:
- **Principal**: Stacks blockchain address
- **Public Key**: 33-byte compressed secp256k1 key

## Getting Started

### Prerequisites
- Stacks blockchain environment
- Clarity smart contract deployment tools
- secp256k1 key pair for signing

### Deployment
1. Deploy the smart contract to Stacks blockchain
2. Contract will initialize with zero registered documents
3. Users can immediately begin registering public keys

## Usage Guide

### 1. Register Your Public Key
Before signing documents, users must register their secp256k1 public key:

```clarity
(contract-call? .document-registry register-cryptographic-public-key public-key-bytes)
```

**Requirements:**
- 33-byte compressed secp256k1 public key
- Valid format (0x02 or 0x03 prefix)

### 2. Register a Document
Document creators can register new documents:

```clarity
(contract-call? .document-registry create-new-document-registration 
  document-hash 
  "Document Title" 
  "Detailed description of the document")
```

**Parameters:**
- `document-hash`: 32-byte unique identifier
- `title`: Up to 256 UTF-8 characters
- `description`: Up to 1024 UTF-8 characters

### 3. Sign a Document
Authorized users can cryptographically sign registered documents:

```clarity
(contract-call? .document-registry create-authenticated-document-signature 
  document-hash 
  signature-bytes 
  "Signature context message")
```

**Requirements:**
- Document must be in "active" status
- User must have registered public key
- Valid cryptographic signature
- No duplicate signatures from same user

### 4. Verify Signatures
Check if specific parties have signed a document:

```clarity
(contract-call? .document-registry verify-multi-party-document-authentication 
  document-hash 
  (list principal1 principal2 principal3))
```

### 5. Document Management
Document creators can:
- Update document metadata
- Revoke document access
- Invalidate specific signatures

## Read-Only Functions

### Document Information
- `fetch-complete-document-information`: Get full document metadata
- `verify-document-registration-status`: Check if document exists
- `calculate-document-signature-total`: Count verified signatures

### Signature Verification  
- `fetch-signature-authentication-record`: Get signature details
- `confirm-user-document-authentication`: Check user signature status
- `perform-cryptographic-signature-verification`: Verify signature cryptographically

### System Statistics
- `fetch-total-system-document-count`: Total registered documents
- `fetch-user-registered-public-key`: Get user's public key

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 400 | `ERR-CRYPTOGRAPHIC-SIGNATURE-VERIFICATION-FAILED` | Invalid signature |
| 400 | `ERR-MALFORMED-PUBLIC-KEY-FORMAT` | Invalid public key format |
| 400 | `ERR-INVALID-FUNCTION-PARAMETERS` | Invalid input parameters |
| 401 | `ERR-UNAUTHORIZED-DOCUMENT-ACCESS` | Not document creator |
| 403 | `ERR-DOCUMENT-ACCESS-REVOKED-STATUS` | Document revoked |
| 404 | `ERR-REQUESTED-DOCUMENT-NOT-FOUND` | Document doesn't exist |
| 404 | `ERR-USER-PUBLIC-KEY-NOT-REGISTERED` | User key not registered |
| 409 | `ERR-DOCUMENT-HASH-ALREADY-REGISTERED` | Duplicate document |
| 409 | `ERR-DUPLICATE-SIGNATURE-FROM-SAME-USER` | User already signed |

## Security Features

### Access Control
- Document creators have exclusive modification rights
- Only registered users can create signatures
- Signature invalidation requires creator authorization

### Cryptographic Integrity
- All signatures verified using secp256k1 recovery
- Composite hashing prevents signature reuse
- Public key format validation prevents malformed keys

### Immutable Audit Trail
- All signatures permanently recorded on blockchain
- Timestamped creation and modification events
- Complete verification history maintained

## Use Cases

### Legal & Compliance
- **Contracts**: Multi-party business agreements
- **Legal Documents**: Court filings and legal instruments  
- **Compliance**: Regulatory documentation with audit trails

### Business Operations
- **HR Documents**: Employment contracts and policy acknowledgments
- **Procurement**: Vendor agreements and purchase orders
- **Finance**: Loan agreements and financial instruments

### Government & Public Sector
- **Official Records**: Government documents and public records
- **Permits & Licenses**: Regulatory approvals and certifications
- **Inter-agency**: Multi-department document coordination

## Technical Specifications

- **Blockchain**: Stacks (Bitcoin-anchored)
- **Language**: Clarity smart contract language
- **Cryptography**: secp256k1 elliptic curve signatures
- **Hashing**: SHA-256 for document identification
- **Encoding**: UTF-8 for text fields

## Limitations

- Maximum 10 parties for batch verification
- Document titles limited to 256 characters
- Descriptions limited to 1024 characters
- Signature context messages limited to 256 characters