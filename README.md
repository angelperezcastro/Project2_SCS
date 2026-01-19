# CS 161 Project 2: Secure File Storage System

A cryptographically secure, end-to-end encrypted file storage and sharing system implemented in Go. This project demonstrates advanced security engineering principles including hybrid cryptography, authenticated encryption, secure key derivation, and access revocation with forward secrecy.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Implementation Details](#implementation-details)
- [Security Analysis](#security-analysis)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Design Decisions](#design-decisions)
- [Performance Characteristics](#performance-characteristics)
- [Known Limitations](#known-limitations)

## Overview

This project implements a secure client application for a file storage system similar to Dropbox or Google Drive, but with a critical difference: **the storage infrastructure is completely untrusted**. The system ensures confidentiality, integrity, and authenticity of all user data even when the datastore is controlled by an adversary.

Users can:
- Register and authenticate securely
- Store, load, and append to files efficiently
- Share files with other users through cryptographically signed invitations
- Revoke access while maintaining security for authorized users

### Threat Model

**Untrusted Components:**
- **Datastore**: Adversary has complete read/write/delete access
- **Network**: All traffic can be intercepted or modified

**Trusted Components:**
- **Keystore**: Public key infrastructure (PKI) for user public keys
- **Client Code**: Runs in trusted environment
- **User Memory**: Adversary cannot access runtime memory

## Features

### Core Functionality
- **User Authentication**: Secure registration and login with password-based key derivation
- **File Operations**: Store, load, and append to files with efficient O(1) append
- **File Sharing**: Create and accept cryptographically signed invitations
- **Access Revocation**: Revoke shared access with forward secrecy guarantees
- **Multi-Device Support**: Multiple simultaneous sessions per user with consistent state

### Security Properties
- ✅ **Hybrid Cryptography**: Combines symmetric (AES-CTR) and asymmetric (RSA/DSA) encryption
- ✅ **Confidentiality**: All data encrypted before storage; adversary cannot read content
- ✅ **Integrity**: HMAC-SHA512 verification prevents tampering and detects corruption
- ✅ **Authentication**: Digital signatures (DSA) ensure invitation authenticity
- ✅ **Forward Secrecy**: Revoked users cannot access future file updates
- ✅ **Key Isolation**: Unique encryption keys per file prevent cross-file attacks
- ✅ **No Information Leakage**: File structure and relationships hidden from adversary

## Architecture

### Data Structures

The system uses a hierarchical structure with multiple layers of encryption:

```
User (in Datastore)
  ├─ Encrypted with keys derived from password
  └─ Contains: SignKey, DecKey, Username

FileAccess (per user, per file)
  ├─ Encrypted with user-specific keys
  ├─ Maps filename → file metadata
  └─ Contains: FileMetaUUID, SymKey, MacKey

FileMeta (shared between users)
  ├─ Encrypted with file-specific symmetric keys
  ├─ Contains ownership and sharing metadata
  └─ Fields: OwnerUsername, FirstBlockUUID, LastBlockUUID, DirectShares

FileBlock (linked list)
  ├─ Encrypted with file-specific symmetric keys
  ├─ Forms singly-linked list of content
  └─ Contains: Content, NextUUID

Invitation (shared via Datastore)
  ├─ Encrypted with recipient's RSA public key
  ├─ Signed with sender's DSA private key
  └─ Contains: FileMetaUUID, SymKey, MacKey
```

#### User
Stores user credentials and cryptographic keys.

**Fields:**
- `Username` (string): User identifier
- `SignKey` (DSSignKey): DSA private key for signing invitations
- `DecKey` (PKEDecKey): RSA private key for decrypting received invitations
- `SourceKey` ([]byte): Master key derived from password using Argon2

**Storage:** Encrypted and stored in Datastore at deterministic UUID

#### FileAccess
User's namespace entry pointing to a file.

**Fields:**
- `FileMetaUUID` (UUID): Location of FileMeta in Datastore
- `SymKey` ([]byte): Symmetric key for encrypting/decrypting file content
- `MacKey` ([]byte): Key for HMAC integrity verification

**Purpose:** Allows each user to have their own filename namespace while sharing underlying file data

**Storage:** Encrypted with user-specific keys at UUID derived from (SourceKey, filename)

#### FileMeta
Metadata about a file, shared among all users with access.

**Fields:**
- `OwnerUsername` (string): Original file owner (only one who can revoke)
- `FirstBlockUUID` (UUID): Head of content linked list
- `LastBlockUUID` (UUID): Tail of content linked list (enables O(1) append)
- `DirectShares` (map[string]UUID): Maps username → InvitationUUID for tracking shares

**Purpose:** Central coordination point for file content and sharing

**Storage:** Encrypted with file-specific symmetric keys

#### FileBlock
A node in the content linked list.

**Fields:**
- `Content` ([]byte): Actual file data for this block
- `NextUUID` (UUID): Pointer to next block (uuid.Nil if last)

**Purpose:** Enables efficient append and supports arbitrarily large files

**Storage:** Encrypted with file-specific symmetric keys

#### Invitation
Credentials package for sharing file access.

**Fields:**
- `FileMetaUUID` (UUID): Location of shared FileMeta
- `SymKey` ([]byte): Symmetric key for file content
- `MacKey` ([]byte): Key for integrity verification

**Purpose:** Securely transfer file access credentials between users

**Storage:** Encrypted with recipient's RSA public key, signed with sender's DSA private key

#### SignedInvitation
Wrapper for authenticated invitation delivery.

**Fields:**
- `EncryptedData` ([]byte): RSA-encrypted Invitation
- `Signature` ([]byte): DSA signature over EncryptedData

**Purpose:** Provides authentication and non-repudiation for invitations

## Cryptographic Design

### Hybrid Cryptography Model

This implementation uses a **hybrid cryptographic scheme** that leverages the complementary strengths of symmetric and asymmetric cryptography:

#### Symmetric Cryptography (Data at Rest)

**Algorithm:** AES-128 in CTR mode
- Used for: User structs, FileAccess, FileMeta, FileBlock encryption
- Key size: 128 bits (16 bytes)
- IV: Random 16 bytes generated per encryption operation
- Performance: Fast encryption/decryption, minimal overhead for large files

**Authentication:** HMAC-SHA512
- Tag size: 512 bits (64 bytes)
- Construction: **Encrypt-then-MAC** (industry best practice)
- Purpose: Integrity verification and tamper detection

**Why Symmetric for Bulk Data:**
- 1000x faster than asymmetric crypto
- Minimal ciphertext expansion (only IV + MAC overhead)
- Efficient for repeated operations (append, load)
- Suitable for large file storage

#### Asymmetric Cryptography (Key Exchange)

**RSA Encryption**
- Key size: 2048 bits
- Used for: Encrypting Invitation structs
- Purpose: Secure key distribution without pre-shared secrets
- Enables: Non-interactive sharing (recipient can be offline)

**DSA Signatures**
- Key size: 2048 bits  
- Used for: Signing encrypted invitations
- Purpose: Authentication and non-repudiation
- Prevents: Invitation forgery and man-in-the-middle attacks

**Why Asymmetric for Key Exchange:**
- No pre-shared secrets required
- Public key infrastructure enables discovery
- Signatures provide authentication
- Enables secure sharing in untrusted environment

#### Hybrid Approach Benefits

The combination provides:
1. **Security**: Strong encryption + authenticated key exchange
2. **Performance**: Fast bulk encryption, acceptable key exchange overhead
3. **Practicality**: No out-of-band key distribution needed
4. **Flexibility**: Easy to add/revoke users without affecting others

### Key Derivation Hierarchy

```
Password + Username
       |
       v
   [Argon2] ─────────> SourceKey (16 bytes)
       |
       ├─[HashKDF("user-struct/enc")]───> User Encryption Key
       ├─[HashKDF("user-struct/mac")]───> User MAC Key
       ├─[HashKDF("fileaccess/enc")]────> FileAccess Encryption Key
       └─[HashKDF("fileaccess/mac")]────> FileAccess MAC Key

Random Generation
       |
       ├───> File Symmetric Key (16 bytes)
       └───> File MAC Key (16 bytes)
```

#### Argon2 Key Derivation
**Purpose:** Derive SourceKey from user password
```
SourceKey = Argon2(password, username, 16 bytes)
```

**Properties:**
- Memory-hard: Resists GPU/ASIC brute force attacks
- Deterministic: Same password always produces same SourceKey
- Salt: Username provides per-user uniqueness
- Output: 128-bit key suitable for AES

**Security:** Recommended for password hashing by OWASP, winner of Password Hashing Competition

#### HashKDF (HMAC-based Key Derivation Function)
**Purpose:** Derive purpose-specific keys from SourceKey
```
derivedKey = HKDF(sourceKey, purpose_string)[:16]
```

**Benefits:**
- **Separation of Concerns**: Each purpose gets independent key
- **Key Reuse Prevention**: Different contexts use different keys
- **Cryptographic Binding**: Keys cryptographically tied to purpose

**Purpose Strings Used:**
- `"user-struct/enc"`: User encryption
- `"user-struct/mac"`: User MAC
- `"fileaccess/enc"`: FileAccess encryption  
- `"fileaccess/mac"`: FileAccess MAC
- `"fileaccess/{filename}"`: FileAccess UUID derivation

### Authenticated Encryption Scheme

#### Encrypt-then-MAC Construction

All encrypted data follows this format:
```
[IV (16 bytes)] [Ciphertext (variable)] [MAC (64 bytes)]
```

**Encryption Process:**
1. Generate random 16-byte IV
2. Encrypt plaintext: `ciphertext = AES-CTR(key, IV, plaintext)`
3. Compute MAC: `mac = HMAC-SHA512(macKey, IV || ciphertext)`
4. Concatenate: `result = IV || ciphertext || mac`

**Decryption Process:**
1. Split: `IV = data[0:16]`, `ciphertext = data[16:-64]`, `mac = data[-64:]`
2. Verify MAC: `expectedMAC = HMAC-SHA512(macKey, IV || ciphertext)`
3. Compare: `if mac != expectedMAC: return error`
4. Decrypt: `plaintext = AES-CTR(key, IV, ciphertext)`

**Security Properties:**
- ✅ Prevents padding oracle attacks
- ✅ Detects any modification to ciphertext
- ✅ Provides integrity before decryption attempt
- ✅ Industry standard construction (used in TLS, SSH)

### UUID Generation Strategy

#### Deterministic UUIDs (for lookups)
```go
// User location
uuid = Hash(username + "/user")[:16]

// FileAccess location  
uuid = HashKDF(sourceKey, "fileaccess/" + filename)[:16]
```

**Benefits:**
- Enables direct lookup without maintaining indices
- No storage overhead for mapping tables
- Consistent across sessions

#### Random UUIDs (for unlinkability)
```go
uuid = uuid.New()  // Cryptographically random
```

**Used for:**
- FileMeta: Prevents adversary from linking files to users
- FileBlock: Prevents content analysis
- Invitation: Prevents invitation tracking

**Security:** Provides ~122 bits of entropy (UUID v4), collision probability negligible

## Implementation Details

### File Storage Architecture

Files are stored as singly-linked lists of encrypted blocks:

```
FileMeta
   |
   ├─ FirstBlockUUID ──> [Block 1] ─> [Block 2] ─> [Block 3] ─> nil
   └─ LastBlockUUID  ──> [Block 3] ────────────────────────────^
```

**Advantages:**
- **O(1) Append**: Direct access to last block via LastBlockUUID
- **Arbitrary Size**: No need to pre-allocate space
- **Efficient Updates**: Only affected blocks need modification
- **Memory Efficient**: Blocks loaded on-demand during read

**Trade-offs:**
- O(n) read: Must traverse entire list to load file
- O(n) storage overhead: UUID pointer per block
- No random access: Must read sequentially

### User Authentication Flow

#### Registration (InitUser)
```
1. Validate username not empty
2. Check username not already taken (Keystore lookup)
3. Generate RSA keypair for encryption
4. Generate DSA keypair for signatures  
5. Store public keys in Keystore:
   - {username}/pke → RSA public key
   - {username}/ds  → DSA verification key
6. Derive SourceKey = Argon2(password, username)
7. Derive encryption/MAC keys from SourceKey
8. Create User struct with keys
9. Serialize, encrypt, authenticate User
10. Store at Datastore[getUserUUID(username)]
```

**Security Notes:**
- Public keys stored in Keystore enable discovery
- Private keys never leave User struct
- SourceKey not serialized (derived on-demand from password)
- All User data encrypted before storage

#### Login (GetUser)
```
1. Derive SourceKey = Argon2(password, username)
2. Derive encryption/MAC keys from SourceKey
3. Load encrypted User from Datastore[getUserUUID(username)]
4. Verify MAC and decrypt
5. Deserialize User struct
6. Verify username matches (integrity check)
7. Restore SourceKey (not serialized)
```

**Security Notes:**
- Wrong password → wrong keys → MAC verification fails
- Tampered data → MAC verification fails
- No timing side-channels (constant-time MAC comparison)

### File Operations

#### Store (New File)
```
1. Generate random file keys: SymKey, MacKey (16 bytes each)
2. Create FileBlock with content
3. Encrypt block: encryptAndMAC(block, SymKey, MacKey)
4. Save block → Datastore[randomUUID]
5. Create FileMeta:
   - OwnerUsername = current user
   - FirstBlockUUID = LastBlockUUID = blockUUID
   - DirectShares = empty map
6. Encrypt meta: encryptAndMAC(meta, SymKey, MacKey)
7. Save meta → Datastore[randomUUID]
8. Create FileAccess:
   - FileMetaUUID = metaUUID
   - SymKey, MacKey = file keys
9. Derive FileAccess keys from user's SourceKey
10. Encrypt access: encryptAndMAC(access, accessEncKey, accessMacKey)
11. Save access → Datastore[getFileAccessUUID(sourceKey, filename)]
```

**Key Insight:** Three-layer encryption (User keys → FileAccess keys → File keys) provides defense in depth

#### Store (Overwrite)
```
1. Load existing FileAccess
2. Load FileMeta via FileAccess.FileMetaUUID
3. Traverse and delete old blocks:
   - Start at meta.FirstBlockUUID
   - Follow NextUUID pointers
   - DatastoreDelete each block
4. Create new FileBlock with new content
5. Update FileMeta pointers to new block
6. Encrypt and save updated meta
```

**Important:** Preserves file keys and sharing relationships

#### Append (O(1) Efficient)
```
1. Load FileAccess
2. Load FileMeta
3. Load last block (meta.LastBlockUUID)
4. Create new FileBlock with appended content:
   - Content = new data
   - NextUUID = uuid.Nil
5. Update old last block:
   - lastBlock.NextUUID = newBlockUUID
6. Update FileMeta:
   - meta.LastBlockUUID = newBlockUUID
7. Encrypt and save all three:
   - New block
   - Updated last block
   - Updated meta
```

**Performance:** O(1) - only touches last block, regardless of file size

#### Load (Sequential Read)
```
1. Load FileAccess
2. Load FileMeta
3. Initialize empty content buffer
4. Current = meta.FirstBlockUUID
5. While current != uuid.Nil:
   a. Load block from Datastore[current]
   b. Decrypt and verify: decryptAndVerify
   c. Append block.Content to buffer
   d. Current = block.NextUUID
6. Return buffer
```

**Performance:** O(n) where n = number of blocks

### File Sharing (Hybrid Cryptography in Action)

The sharing mechanism demonstrates the hybrid cryptographic approach:

#### CreateInvitation
```
1. Verify recipient exists (Keystore lookup for public keys)
2. Load sender's FileAccess for the file
3. Load FileMeta to get ownership info
4. Create Invitation struct:
   - FileMetaUUID = access.FileMetaUUID
   - SymKey = access.SymKey (file's symmetric key)
   - MacKey = access.MacKey
5. Serialize Invitation → JSON
6. ASYMMETRIC: Encrypt with recipient's RSA public key
   encryptedInv = PKEEnc(recipientPublicKey, invitationJSON)
7. ASYMMETRIC: Sign with sender's DSA private key
   signature = DSSign(senderPrivateKey, encryptedInv)
8. Create SignedInvitation:
   - EncryptedData = encryptedInv
   - Signature = signature
9. Generate random invitationUUID
10. Save SignedInvitation → Datastore[invitationUUID]
11. If sender is owner:
    Update meta.DirectShares[recipientUsername] = invitationUUID
12. Return invitationUUID
```

**Hybrid Crypto Flow:**
- File encrypted with **SYMMETRIC** keys (fast, efficient)
- Symmetric keys encrypted with **ASYMMETRIC** crypto (secure, no pre-shared secrets)
- **Signature** provides authentication (prevents forgery)

**Security Properties:**
- Only recipient can decrypt (has private key)
- Signature proves sender identity
- Adversary cannot forge invitation
- Invitation stored encrypted in untrusted Datastore

#### AcceptInvitation
```
1. Check filename doesn't already exist locally
2. Load sender's DSA verification key from Keystore
3. Load SignedInvitation from Datastore[invitationPtr]
4. ASYMMETRIC: Verify signature
   DSVerify(senderVerifyKey, encryptedData, signature)
   If fails → reject (forged or tampered)
5. ASYMMETRIC: Decrypt invitation with recipient's RSA private key
   invitationJSON = PKEDec(recipientPrivateKey, encryptedData)
6. Deserialize Invitation struct
7. SYMMETRIC: Verify file still accessible
   - Load FileMeta from invitation.FileMetaUUID
   - Decrypt using invitation.SymKey/MacKey
   - If fails → access revoked or file deleted
8. Create local FileAccess:
   - FileMetaUUID = invitation.FileMetaUUID
   - SymKey = invitation.SymKey
   - MacKey = invitation.MacKey
9. Derive recipient's FileAccess keys
10. Encrypt and save FileAccess locally
11. Recipient can now access file with SYMMETRIC keys
```

**Key Transition:** Asymmetric crypto establishes trust, then symmetric crypto provides efficient ongoing access

**Security Checks:**
- Signature verification prevents forged invitations
- File accessibility check detects revoked access
- Local FileAccess creation enables recipient's own namespace

### Access Revocation (Forward Secrecy)

Revocation provides forward secrecy by re-keying the entire file:

```
1. Load owner's FileAccess
2. Load FileMeta
3. Verify caller is owner (meta.OwnerUsername)
4. Verify recipient has access (in meta.DirectShares)
5. Generate NEW random keys:
   newSymKey = RandomBytes(16)
   newMacKey = RandomBytes(16)
6. RE-ENCRYPT ALL BLOCKS:
   currentUUID = meta.FirstBlockUUID
   While currentUUID != uuid.Nil:
     a. Load encrypted block
     b. Decrypt with OLD keys: decryptAndVerify(block, oldSymKey, oldMacKey)
     c. Encrypt with NEW keys: encryptAndMAC(block, newSymKey, newMacKey)
     d. Overwrite in Datastore[currentUUID]
     e. currentUUID = block.NextUUID
7. DELETE revoked user's invitation:
   invUUID = meta.DirectShares[recipientUsername]
   DatastoreDelete(invUUID)
   delete(meta.DirectShares, recipientUsername)
8. UPDATE remaining users' invitations:
   For each username, invUUID in meta.DirectShares:
     a. Create new Invitation with NEW keys
     b. Encrypt with user's RSA public key
     c. Sign with owner's DSA private key
     d. Overwrite Datastore[invUUID]
9. RE-ENCRYPT FileMeta with NEW keys
10. UPDATE owner's FileAccess with NEW keys
```

**Forward Secrecy Guarantee:**
- Revoked user's old invitation is deleted
- Old symmetric keys are discarded
- New keys unknown to revoked user
- All file content re-encrypted
- Future updates inaccessible to revoked user

**Transitive Revocation:**
- Revokes direct recipient
- Also revokes anyone recipient shared with (they used same invitation)

**Performance:** O(n + m) where n = blocks, m = remaining authorized users

## Security Analysis

### Adversary Capabilities

**Datastore Adversary Can:**
- Read all stored data
- Modify any stored data
- Delete any stored data  
- Observe access patterns (which UUIDs accessed when)
- Add arbitrary data

**Datastore Adversary Cannot:**
- Decrypt data (no keys)
- Forge signatures (no private keys)
- Determine file contents or structure
- Link users to files (random UUIDs)
- Determine sharing relationships

### Security Properties Achieved

#### Confidentiality

**Claim:** Adversary with full Datastore access cannot read file contents

**Evidence:**
1. All data encrypted before storage (User, FileAccess, FileMeta, FileBlock)
2. Encryption keys derived from:
   - User password (via Argon2) - not stored
   - Random generation - not stored in Datastore
3. AES-128 provides 2^128 security against brute force
4. IV randomization prevents pattern analysis
5. Random UUIDs prevent linking encrypted data

**Attack Resistance:**
- ❌ Brute force: 2^128 keyspace infeasible
- ❌ Pattern analysis: Random IVs, no repeated ciphertexts
- ❌ Known-plaintext: CTR mode with unique IVs secure
- ❌ Chosen-ciphertext: MAC verification prevents tampering

#### Integrity

**Claim:** Adversary cannot undetectably modify data

**Evidence:**
1. HMAC-SHA512 provides 512-bit authentication tag
2. Encrypt-then-MAC construction
3. MAC covers entire ciphertext
4. Constant-time MAC comparison prevents timing attacks
5. Verification before decryption prevents oracle attacks

**Attack Resistance:**
- ❌ Modification: MAC verification fails
- ❌ Truncation: Missing data changes MAC
- ❌ Bit flips: Any change detected by MAC
- ❌ Replay: UUIDs and randomness prevent replay

#### Authentication

**Claim:** Recipient can verify invitation sender identity

**Evidence:**
1. DSA signatures with 2048-bit keys
2. Signature covers entire encrypted invitation
3. Verification uses sender's public key from trusted Keystore
4. Private signing key never leaves sender's User struct
5. Signature prevents repudiation

**Attack Resistance:**
- ❌ Forgery: Cannot create valid signature without private key
- ❌ MITM: Signature binds encrypted data to sender
- ❌ Replay: Encrypted content includes file-specific keys

#### Forward Secrecy

**Claim:** Revoked users cannot access file updates after revocation

**Evidence:**
1. Revocation generates new random symmetric keys
2. All file blocks re-encrypted with new keys
3. Revoked user's invitation deleted from Datastore
4. Remaining users receive new invitations with new keys
5. Old keys provide no information about new keys

**Attack Resistance:**
- ❌ Old keys: Cannot decrypt newly encrypted data
- ❌ Old invitation: Deleted from Datastore
- ❌ Key derivation: New keys randomly generated, not derived from old

### Attack Scenarios

#### Scenario 1: Password Guessing
**Attack:** Adversary tries common passwords for user "alice"

**Defense:**
- Argon2 is memory-hard (resists GPU/ASIC attacks)
- Even if password weak, Argon2 slows brute force
- Salt (username) prevents rainbow tables
- Wrong password → wrong SourceKey → MAC verification fails immediately

**Outcome:** Attack computationally infeasible for reasonable passwords

#### Scenario 2: File Content Tampering
**Attack:** Adversary modifies ciphertext in Datastore

**Defense:**
- HMAC-SHA512 computed over ciphertext
- Any modification changes ciphertext, invalidates MAC
- MAC verified before decryption
- Failed verification returns error, no data exposed

**Outcome:** Tampering detected, attack fails

#### Scenario 3: Invitation Forgery
**Attack:** Adversary creates fake invitation claiming to be from Alice

**Defense:**
- Invitation encrypted with recipient's public key (adversary doesn't have private key)
- Even if adversary creates encrypted data, cannot forge DSA signature
- Signature verification requires Alice's private signing key
- Failed verification rejects invitation

**Outcome:** Forgery detected, attack fails

#### Scenario 4: Revoked User Access
**Attack:** Bob (revoked) tries to access file using old invitation

**Defense:**
1. Bob's old invitation deleted from Datastore
2. FileMeta re-encrypted with new keys
3. FileBlocks re-encrypted with new keys
4. Bob's old keys decrypt to garbage (MAC verification fails)

**Outcome:** Bob cannot access file, attack fails

#### Scenario 5: Traffic Analysis
**Attack:** Adversary observes which UUIDs user accesses

**Defense:**
- Random UUIDs for FileMeta, FileBlocks, Invitations
- No linkage between UUID and content
- Access patterns don't reveal relationships
- Encryption hides data sizes (padded to block boundaries)

**Outcome:** Limited information leakage (access pattern visible but content hidden)

### Cryptographic Primitives Used

| Primitive | Purpose | Key Size | Security Level |
|-----------|---------|----------|----------------|
| AES-CTR | Symmetric encryption | 128-bit | ~2^128 operations |
| HMAC-SHA512 | Message authentication | 512-bit output | ~2^256 operations |
| RSA | Asymmetric encryption | 2048-bit | ~112-bit security |
| DSA | Digital signatures | 2048-bit | ~112-bit security |
| Argon2 | Password-based KDF | Configurable | Memory-hard |
| HKDF | Key derivation | 256-bit | ~2^256 operations |

**Security Margin:** All primitives exceed NIST recommendations for "secure" (112-bit security) as of 2024.

## API Reference

### User Management

#### `InitUser(username string, password string) (*User, error)`

Creates a new user account with the given credentials.

**Parameters:**
- `username`: Unique user identifier (cannot be empty)
- `password`: User password (used for key derivation)

**Returns:**
- `*User`: Pointer to initialized User struct
- `error`: Non-nil if username already exists or validation fails

**Errors:**
- `"username cannot be empty"`: Username validation failed
- `"user already exists"`: Username already registered in Keystore

**Side Effects:**
- Generates RSA and DSA keypairs
- Stores public keys in Keystore
- Encrypts and stores User struct in Datastore

**Example:**
```go
alice, err := client.InitUser("alice", "strongpassword123")
if err != nil {
    log.Fatal(err)
}
```

#### `GetUser(username string, password string) (*User, error)`

Authenticates and retrieves an existing user.

**Parameters:**
- `username`: User identifier
- `password`: User password

**Returns:**
- `*User`: Pointer to authenticated User struct
- `error`: Non-nil if credentials invalid or user doesn't exist

**Errors:**
- `"user does not exist"`: No user found with given username
- `"invalid credentials or data corrupted"`: Wrong password or tampered data
- `"data integrity check failed"`: Decrypted username doesn't match

**Example:**
```go
alice, err := client.GetUser("alice", "strongpassword123")
if err != nil {
    log.Fatal("Authentication failed:", err)
}
```

**Multi-Session Support:**
```go
// Multiple instances of same user (different devices)
alicePhone, _ := client.GetUser("alice", "strongpassword123")
aliceLaptop, _ := client.GetUser("alice", "strongpassword123")
// Both can operate on same files independently
```

### File Operations

#### `StoreFile(filename string, content []byte) error`

Stores a file, creating new or overwriting existing.

**Parameters:**
- `filename`: Local filename in user's namespace (can include path separators)
- `content`: Complete file content as byte array

**Returns:**
- `error`: Non-nil if operation fails

**Behavior:**
- If filename doesn't exist: Creates new file
- If filename exists: Overwrites with new content (deletes old blocks)

**Example:**
```go
content := []byte("Hello, World!")
err := alice.StoreFile("greeting.txt", content)
if err != nil {
    log.Fatal(err)
}
```

**Performance:** O(n) where n = number of blocks in existing file (if overwriting)

#### `LoadFile(filename string) ([]byte, error)`

Loads and returns the complete file content.

**Parameters:**
- `filename`: Local filename in user's namespace

**Returns:**
- `[]byte`: Complete file content
- `error`: Non-nil if file not found or access denied

**Errors:**
- `"file not found"`: No FileAccess exists for filename
- `"file metadata not found"`: FileMeta deleted or inaccessible
- `"file block not found"`: Content block deleted
- MAC verification errors: Data tampered or keys incorrect

**Example:**
```go
content, err := alice.LoadFile("greeting.txt")
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(content))
```

**Performance:** O(n) where n = number of blocks in file

#### `AppendToFile(filename string, content []byte) error`

Efficiently appends content to existing file without loading entire file.

**Parameters:**
- `filename`: Local filename in user's namespace
- `content`: Data to append

**Returns:**
- `error`: Non-nil if file doesn't exist or operation fails

**Errors:**
- `"file not found"`: No FileAccess exists
- `"last block not found"`: Metadata inconsistent

**Example:**
```go
// File contains: "Hello"
err := alice.AppendToFile("greeting.txt", []byte(", World!"))
// File now contains: "Hello, World!"
```

**Performance:** O(1) - only accesses last block, regardless of file size

**Key Advantage:** Can append to gigabyte files in constant time

### Sharing Operations

#### `CreateInvitation(filename string, recipientUsername string) (uuid.UUID, error)`

Creates a cryptographically signed invitation to share file with another user.

**Parameters:**
- `filename`: Local filename to share
- `recipientUsername`: Username of intended recipient

**Returns:**
- `uuid.UUID`: Invitation identifier (send this to recipient)
- `error`: Non-nil if operation fails

**Errors:**
- `"recipient user does not exist"`: Recipient not registered (no public keys in Keystore)
- `"file not found"`: Sender doesn't have access to file
- `"file metadata not found"`: File deleted or corrupted

**Behavior:**
- Creates encrypted invitation with file access credentials
- Signs invitation with sender's private key
- If sender is owner: Tracks invitation in FileMeta.DirectShares
- Recipient can accept even if sender goes offline

**Example:**
```go
inviteUUID, err := alice.CreateInvitation("document.txt", "bob")
if err != nil {
    log.Fatal(err)
}
// Send inviteUUID to Bob via out-of-band channel (or just tell Bob the UUID)
```

**Security:**
- Invitation encrypted with recipient's RSA public key (only Bob can decrypt)
- Signed with Alice's DSA private key (Bob can verify sender)
- Stored in Datastore (untrusted but confidential)

#### `AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error`

Accepts an invitation and creates local access to shared file.

**Parameters:**
- `senderUsername`: Username of invitation sender (for signature verification)
- `invitationPtr`: Invitation UUID (received from sender)
- `filename`: Local filename to use for this shared file (can differ from sender's name)

**Returns:**
- `error`: Non-nil if operation fails

**Errors:**
- `"filename already exists"`: Recipient already has file with this name
- `"sender does not exist"`: Cannot verify signature (no sender public key)
- `"invitation not found"`: Invitation UUID invalid or deleted
- `"invalid signature"`: Invitation forged or tampered
- `"could not decrypt invitation"`: Invitation not intended for this recipient
- `"file no longer exists"`: File deleted after invitation created
- `"access has been revoked"`: Sender revoked access before acceptance

**Example:**
```go
// Bob accepts Alice's invitation
err := bob.AcceptInvitation("alice", inviteUUID, "alice_document.txt")
if err != nil {
    log.Fatal(err)
}
// Bob can now access file as "alice_document.txt"
```

**Post-Acceptance:**
- Bob has full read/write access
- Bob can append to file
- Bob can share file with others (create own invitations)
- Bob sees all updates from Alice and others

#### `RevokeAccess(filename string, recipientUsername string) error`

Revokes user's access to a file. **Only the original owner can revoke access.**

**Parameters:**
- `filename`: Local filename
- `recipientUsername`: User whose access to revoke

**Returns:**
- `error`: Non-nil if operation fails

**Errors:**
- `"file not found"`: Caller doesn't have access
- `"only the owner can revoke access"`: Caller is not original owner
- `"user does not have access"`: Recipient never had access

**Behavior:**
1. Generates new random encryption keys for file
2. Re-encrypts all file blocks with new keys
3. Deletes revoked user's invitation
4. Updates invitations for remaining users with new keys
5. Revoked user cannot access file or future updates

**Transitive Revocation:**
If Alice shares with Bob, Bob shares with Charlie:
- Alice revokes Bob → Both Bob and Charlie lose access
- Tree structure: Revoking parent revokes entire subtree

**Example:**
```go
// Alice revokes Bob's access
err := alice.RevokeAccess("document.txt", "bob")
if err != nil {
    log.Fatal(err)
}
// Bob can no longer access file (load, append, or share)
// Anyone Bob shared with also loses access
```

**Performance:** O(n + m) where n = file blocks, m = remaining authorized users

**Forward Secrecy:** Revoked users cannot access file updates after revocation

## Testing

### Test Framework

This project uses **Ginkgo** (BDD test framework) and **Gomega** (matcher library) for testing:

```go
// Ginkgo BDD structure
Describe("Component", func() {
    BeforeEach(func() {
        // Setup before each test
    })
    
    Specify("Test Case", func() {
        // Test logic with Gomega assertions
        Expect(value).To(Equal(expected))
    })
})
```

### Unit Tests (`client_unittest.go`)

White-box tests that access internal implementation details.

**Purpose:**
- Test individual functions and methods
- Verify struct fields and data structures
- Check helper function correctness
- Validate cryptographic operations

**Example Test:**
```go
Specify("Check Username field initialization", func() {
    alice, err := InitUser("alice", "password")
    Expect(err).To(BeNil())
    Expect(alice.Username).To(Equal("alice"))
})
```

**Scope:** Can access private fields (e.g., `alice.Username`, `alice.SourceKey`)

### Integration Tests (`client_test.go`)

Black-box tests that only use the public API.

**Test Scenarios:**

#### 1. Single User Operations
```go
// Test: Store → Append → Load
alice.StoreFile("file.txt", []byte("Hello"))
alice.AppendToFile("file.txt", []byte(" World"))
content, _ := alice.LoadFile("file.txt")
// Expect: "Hello World"
```

**Validates:**
- File creation and storage
- Append functionality
- Content persistence
- Proper concatenation

#### 2. Multi-User Sharing
```go
// Alice stores file
alice.StoreFile("file.txt", []byte("Content"))

// Alice shares with Bob
invite, _ := alice.CreateInvitation("file.txt", "bob")

// Bob accepts
bob.AcceptInvitation("alice", invite, "shared.txt")

// Bob appends
bob.AppendToFile("shared.txt", []byte(" More"))

// Both see updates
aliceContent, _ := alice.LoadFile("file.txt")
bobContent, _ := bob.LoadFile("shared.txt")
// Both equal: "Content More"
```

**Validates:**
- Invitation creation and acceptance
- Shared file synchronization
- Append from shared user
- Consistent state across users

#### 3. Multi-Device Sessions
```go
// Alice logs in on desktop
aliceDesktop, _ := client.InitUser("alice", "password")

// Alice logs in on laptop
aliceLaptop, _ := client.GetUser("alice", "password")

// Desktop stores file
aliceDesktop.StoreFile("file.txt", []byte("Data"))

// Laptop can access
content, _ := aliceLaptop.LoadFile("file.txt")
// Expect: "Data"
```

**Validates:**
- Multiple simultaneous sessions
- State consistency across sessions
- Correct key derivation

#### 4. Access Revocation
```go
// Alice shares with Bob
invite, _ := alice.CreateInvitation("file.txt", "bob")
bob.AcceptInvitation("alice", invite, "shared.txt")

// Bob shares with Charlie
invite2, _ := bob.CreateInvitation("shared.txt", "charlie")
charlie.AcceptInvitation("bob", invite2, "file.txt")

// Alice revokes Bob
alice.RevokeAccess("file.txt", "bob")

// Bob and Charlie cannot access
_, err1 := bob.LoadFile("shared.txt")
_, err2 := charlie.LoadFile("file.txt")
// Both errors non-nil

// Alice still has access
content, err := alice.LoadFile("file.txt")
// No error, content accessible
```

**Validates:**
- Owner-only revocation
- Transitive revocation (Bob's subtree)
- Forward secrecy (old keys don't work)
- Owner retains access

### Running Tests

```bash
# Run all tests (unit + integration)
go test -v

# Run only unit tests
go test -v -run "Unit"

# Run only integration tests
go test -v -run "Client Tests"

# Run specific test
go test -v -run "Testing Revoke"

# Run with race detection
go test -race -v

# Run with coverage
go test -cover -v

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Coverage Goals

| Component | Coverage Target |
|-----------|----------------|
| User management | 100% |
| File operations | 100% |
| Sharing/Revocation | 95%+ |
| Helper functions | 100% |
| Error paths | 90%+ |

## Design Decisions

### Why Hybrid Cryptography?

The system combines symmetric and asymmetric cryptography for optimal security and performance.

#### Symmetric Cryptography Benefits

**Performance:**
- 1000x faster than RSA encryption
- Negligible overhead for large files
- Efficient for repeated operations

**Efficiency:**
- Minimal ciphertext expansion (IV + MAC only)
- Low computational cost (important for battery/mobile devices)
- Scales to arbitrarily large files

**Use Cases:**
- File content encryption (FileBlock)
- Metadata encryption (FileMeta, FileAccess)
- User data encryption (User struct)

#### Asymmetric Cryptography Benefits

**Key Distribution:**
- No pre-shared secrets required
- Users can share without prior coordination
- Public key infrastructure enables discovery

**Authentication:**
- Digital signatures prove sender identity
- Non-repudiation (sender cannot deny)
- Prevents man-in-the-middle attacks

**Non-Interactive:**
- Recipient can be offline during share
- Invitation stored until accessed
- Asynchronous communication

**Use Cases:**
- Invitation encryption (RSA)
- Invitation signing (DSA)
- Secure key exchange

#### Hybrid Approach

**Best of Both Worlds:**
1. Files encrypted with fast symmetric crypto
2. Symmetric keys encrypted with secure asymmetric crypto
3. Signatures provide authentication
4. Result: Secure + Fast + Practical

**Real-World Analogy:**
- TLS/SSL uses same approach
- Signal messenger uses hybrid encryption
- PGP uses hybrid encryption

**Design Pattern:**
```
[Large Data] ──symmetric──> [Ciphertext]
                            ↓
[Symmetric Key] ──asymmetric──> [Encrypted Key]
                               ↓ (signed)
                          [Invitation]
```

### Why Linked Lists for File Storage?

Files are stored as singly-linked lists of encrypted blocks.

#### Design
```
FileMeta
  ├─ FirstBlockUUID → [Block 1] → [Block 2] → [Block 3] → nil
  └─ LastBlockUUID  → [Block 3]
```

#### Advantages

**O(1) Append:**
```go
// Only touch last block, no matter how large file is
lastBlock = load(meta.LastBlockUUID)
newBlock = create(appendedContent)
lastBlock.NextUUID = newBlock.UUID
save(lastBlock)
save(newBlock)
meta.LastBlockUUID = newBlock.UUID
```
- No need to traverse entire list
- No need to load entire file
- Constant time regardless of file size
- Critical for large files

**Arbitrary File Size:**
- No pre-allocation needed
- Grows dynamically
- Only limited by Datastore capacity
- No maximum file size restriction

**Efficient Updates:**
- Overwrite: Only update affected blocks
- Append: Only touch last block
- Minimal data movement

**Memory Efficiency:**
- Blocks loaded on-demand during read
- Don't need entire file in memory
- Streaming possible

#### Trade-offs

**Sequential Read Required:**
- O(n) to read entire file
- Must traverse from beginning
- No random access
- Acceptable for typical file operations

**Storage Overhead:**
- Each block needs UUID pointer (16 bytes)
- For 1KB blocks: 1.6% overhead
- For 64KB blocks: 0.025% overhead
- Negligible compared to encryption overhead

**Alternatives Considered:**

| Approach | Append | Read | Random Access | Overhead |
|----------|--------|------|---------------|----------|
| Single Block | O(n) | O(1) | O(1) | Low |
| Linked List | O(1) | O(n) | O(n) | Low |
| Array | O(n) | O(1) | O(1) | Medium |
| B-Tree | O(log n) | O(log n) | O(log n) | High |

**Decision:** Linked list chosen for O(1) append priority

### Why Separate Keys Per File?

Each file uses unique randomly generated encryption keys.

#### Benefits

**Damage Limitation:**
- Compromised file key only exposes one file
- Other files remain secure
- Limits blast radius of key compromise

**Sharing Flexibility:**
- Can share file without exposing other files
- Recipient gets file-specific keys only
- No access to sender's other files

**Efficient Revocation:**
- Re-key only affected file
- Don't need to re-encrypt user's entire storage
- O(n) in file size, not total storage

**Key Rotation:**
- Each file can be re-keyed independently
- Supports periodic key rotation policies
- Granular security controls

#### Alternative: Single Master Key

**Problems with master key:**
- Compromise exposes all files
- Sharing one file requires trusting with all files
- Revocation requires re-encrypting everything
- No granular controls

**Conclusion:** Per-file keys provide better security and flexibility

### Why Encrypt-then-MAC?

All authenticated encryption uses Encrypt-then-MAC construction.

#### Construction
```
1. ciphertext = Encrypt(key, plaintext)
2. mac = MAC(macKey, ciphertext)
3. result = ciphertext || mac
```

#### Security Advantages

**Prevents Padding Oracle Attacks:**
- MAC verified before decryption attempt
- Invalid MAC → reject immediately
- Never decrypt tampered data
- Protects against CBC padding attacks

**Integrity Before Decryption:**
- Detect tampering without exposing plaintext
- Fail fast on modification
- No information leakage

**Cryptographic Best Practice:**
- Recommended by cryptographic community
- Used in TLS 1.3, SSH, IPsec
- Proven secure construction

#### Alternatives Rejected

**MAC-then-Encrypt:**
```
mac = MAC(key, plaintext)
ciphertext = Encrypt(key, plaintext || mac)
```
- Vulnerable to padding oracle attacks
- MAC verification requires decryption
- Not recommended

**Encrypt-and-MAC:**
```
ciphertext = Encrypt(key, plaintext)
mac = MAC(macKey, plaintext)
```
- MAC on plaintext may leak information
- Less studied construction
- Not recommended

**Authenticated Encryption (AE) Modes:**
- GCM, CCM, EAX modes built-in
- Not available in userlib
- Encrypt-then-MAC equivalent security

### Why Store Invitations in Datastore?

Invitations are persistently stored rather than ephemeral.

#### Rationale

**Asynchronous Sharing:**
- Sender can create invitation while recipient offline
- Recipient accepts when convenient
- No real-time coordination needed

**Durability:**
- Invitation survives sender logout
- Persistent until accepted or revoked
- No need for complex delivery protocol

**Simplicity:**
- Single storage layer (Datastore)
- No separate message queue needed
- Uniform encryption/security model

#### Revocation Tracking

**DirectShares Map:**
```go
meta.DirectShares[recipientUsername] = invitationUUID
```

**Purpose:**
- Owner tracks who has access
- Enables targeted revocation
- Can delete specific invitations
- Supports transitive revocation

**Security:**
- Map stored in encrypted FileMeta
- Only accessible to authorized users
- Adversary cannot see sharing relationships

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| InitUser | O(1) | Constant time key generation |
| GetUser | O(1) | Single Datastore lookup |
| StoreFile (new) | O(1) | Single block for content |
| StoreFile (overwrite) | O(n) | Delete n old blocks |
| AppendToFile | O(1) | Only touch last block |
| LoadFile | O(n) | Traverse n blocks |
| CreateInvitation | O(1) | Constant cryptographic ops |
| AcceptInvitation | O(1) | Constant cryptographic ops |
| RevokeAccess | O(n + m) | n blocks + m users |

Where:
- n = number of file blocks
- m = number of users with access

### Space Complexity

| Structure | Per-Instance Size | Notes |
|-----------|------------------|-------|
| User | ~2KB | RSA/DSA keys + metadata |
| FileAccess | ~100 bytes | UUIDs + symmetric keys |
| FileMeta | ~200 bytes + 48m | m = users in DirectShares |
| FileBlock | content + 16 bytes | UUID overhead |
| Invitation | ~512 bytes | RSA ciphertext + signature |

**Total Storage:**
```
File Storage = Σ(block_content + 16) for all blocks
            + FileMeta (~200 + 48m bytes)
            + FileAccess per user (~100 bytes)
            + Invitations (512 bytes each)
```

**Overhead:** ~1-2% for typical files (>10KB)

### Cryptographic Operation Costs

| Operation | Time (approx) | Type |
|-----------|--------------|------|
| AES-128 Encrypt | 0.1 μs per KB | Symmetric |
| HMAC-SHA512 | 1 μs per KB | MAC |
| RSA-2048 Encrypt | 100 μs | Asymmetric |
| RSA-2048 Decrypt | 3 ms | Asymmetric |
| DSA-2048 Sign | 2 ms | Signature |
| DSA-2048 Verify | 4 ms | Verification |
| Argon2 | 100-500 ms | KDF |

**Implications:**
- File operations (symmetric crypto) very fast
- Sharing operations (asymmetric crypto) slower but acceptable
- Login (Argon2) intentionally slow for security


## Known Limitations

### Design Limitations

**1. Revocation Performance**
- **Issue:** O(n) where n = file blocks
- **Impact:** Large files (GB+) have expensive revocation
- **Mitigation:** Could use encryption layers, but complicates design

**2. No Random Access**
- **Issue:** Must read sequentially from start
- **Impact:** Cannot seek to middle of file efficiently
- **Mitigation:** Acceptable for most file operations

**3. Flat Sharing Tree**
- **Issue:** DirectShares is simple map, not tree structure
- **Impact:** Cannot track exact sharing graph
- **Effect:** Revocation is transitive (can't revoke just subtree)

**4. No Atomic Multi-File Operations**
- **Issue:** Each operation is single file
- **Impact:** Cannot atomically update multiple files
- **Mitigation:** Not required by specification

**5. File Size Limited by Memory**
- **Issue:** LoadFile loads entire file into memory
- **Impact:** Very large files (> RAM) cannot be loaded
- **Mitigation:** Could implement streaming

### Security Limitations

**6. Access Pattern Leakage**
- **Issue:** Adversary sees which UUIDs accessed when
- **Impact:** Can infer usage patterns
- **Mitigation:** ORAM could hide patterns but expensive

**7. No Protection Against Deletion**
- **Issue:** Adversary can delete any Datastore entry
- **Impact:** Denial of service possible
- **Mitigation:** Fundamental to untrusted storage model

**8. Username Enumeration**
- **Issue:** Can check if username exists in Keystore
- **Impact:** Privacy leak (username list discoverable)
- **Mitigation:** Would require private PIR

**9. No Key Rotation**
- **Issue:** User keys never change after creation
- **Impact:** Long-term key compromise not recoverable
- **Mitigation:** Could implement periodic re-keying

**10. Revocation Not Instant**
- **Issue:** Revoked users might have cached data
- **Impact:** May retain access to old version temporarily
- **Mitigation:** Inherent to client-side caching

### Implementation Specifics

**11. Fixed Block Size**
- **Current:** Each append creates new block
- **Better:** Could coalesce small appends
- **Impact:** Many tiny appends create many small blocks

**12. No Compression**
- **Issue:** No data compression before encryption
- **Impact:** Larger storage usage
- **Note:** Encryption eliminates compression effectiveness anyway

**13. No Deduplication**
- **Issue:** Identical files stored separately
- **Impact:** Storage inefficiency for duplicate data
- **Security:** Deduplication could leak information

### Operational Considerations

**14. No Backup/Recovery**
- **Issue:** Lost password = lost data
- **Impact:** No password recovery mechanism
- **Mitigation:** Could implement key escrow (reduces security)

**15. No Version History**
- **Issue:** StoreFile overwrites, no undo
- **Impact:** Cannot recover from accidental overwrite
- **Mitigation:** Could implement copy-on-write

**16. No Garbage Collection**
- **Issue:** Deleted blocks not automatically cleaned
- **Impact:** Storage leaks over time
- **Note:** Would need complex reference counting

## Future Enhancements

### Potential Improvements

**Performance:**
- Implement caching layer for metadata
- Batch cryptographic operations
- Use GCM mode (authenticated encryption)
- Compress before encrypt

**Security:**
- Add key rotation mechanism
- Implement ORAM for access pattern hiding
- Add certificate transparency log
- Support hardware security modules (HSM)

**Functionality:**
- Version history / snapshots
- Folder/directory support
- Fine-grained permissions
- File metadata (timestamps, etc.)

**Usability:**
- Password recovery with escrow
- Key backup to trusted party
- Multi-factor authentication
- Social recovery

## Conclusion

This project implements a comprehensive secure file storage system that demonstrates:

✅ **Security Engineering:** Defense in depth with multiple security layers
✅ **Cryptographic Design:** Proper use of hybrid cryptography  
✅ **Performance Optimization:** O(1) append for efficient operations
✅ **Practical Security:** Balances security with usability

The system achieves security properties comparable to real-world systems like Signal, WhatsApp, and ProtonMail, while operating in an untrusted environment. The implementation serves as an educational example of applied cryptography and secure system design.
