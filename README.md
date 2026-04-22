# Unity Encryption Manager

A simple encryption and hashing library for Unity.

## Installation

- [Latest Release](https://github.com/vanhaodev/unity-encryption-manager/releases/latest)
- [All Releases](https://github.com/vanhaodev/unity-encryption-manager/releases)

## Encryption

### Quick Start

```csharp
using vanhaodev.encryptionmanager;

// Register with auto-generated key
EncryptionManager.GetAesAutoKey();

// Encrypt & Decrypt
var encrypted = EncryptionManager.Encrypt(EncryptType.Aes, "Hello World!");
var decrypted = EncryptionManager.Decrypt(EncryptType.Aes, encrypted);
```

### AES Encryption

```csharp
// Option 1: Auto-generate key (recommended for new projects)
byte[] key = EncryptionManager.GetAesAutoKey();
// Save this key somewhere secure for later use!

// Option 2: Use your own string key (easy for beginners)
EncryptionManager.RegisterAes("mySecretPassword123");

// Option 3: Use byte[] key (for advanced users)
EncryptionManager.RegisterAes(myKeyBytes);

// Encrypt string -> returns Base64
string encrypted = EncryptionManager.Encrypt(EncryptType.Aes, "secret data");

// Decrypt Base64 -> returns original string
string decrypted = EncryptionManager.Decrypt(EncryptType.Aes, encrypted);

// Encrypt/Decrypt bytes
byte[] encryptedBytes = EncryptionManager.Encrypt(EncryptType.Aes, dataBytes);
byte[] decryptedBytes = EncryptionManager.Decrypt(EncryptType.Aes, encryptedBytes);
```

**Note:** IV is automatically generated per encryption and embedded in the output. You only need to manage the key.

### XOR Encryption

Simple and fast, suitable for basic obfuscation.

```csharp
// Auto-generate key
byte key = EncryptionManager.GetXorAutoKey();

// Or use your own key
EncryptionManager.RegisterXor(0x5A);

// Encrypt & Decrypt
var encrypted = EncryptionManager.Encrypt(EncryptType.Xor, "data");
var decrypted = EncryptionManager.Decrypt(EncryptType.Xor, encrypted);
```

### Async (for large data)

Use async methods to avoid freezing the main thread:

```csharp
var encrypted = await EncryptionManager.EncryptAsync(EncryptType.Aes, largeData);
var decrypted = await EncryptionManager.DecryptAsync(EncryptType.Aes, encrypted);
```

## Hashing

### Quick Start

```csharp
using vanhaodev.encryptionmanager;

// Register PBKDF2
HashManager.RegisterPbkdf2();

// Hash password
string hash = HashManager.Hash(HashType.Pbkdf2, "myPassword123");

// Verify password
bool isValid = HashManager.Verify(HashType.Pbkdf2, "myPassword123", hash);
```

### PBKDF2 Hashing

Secure password hashing with automatic salt.

```csharp
// Register with default iterations (10000)
HashManager.RegisterPbkdf2();

// Or with custom iterations (higher = more secure but slower)
HashManager.RegisterPbkdf2(50000);

// Hash - returns combined salt+hash as Base64
string hash = HashManager.Hash(HashType.Pbkdf2, "password");
// Save this hash to your database

// Verify - compares password against stored hash
bool isValid = HashManager.Verify(HashType.Pbkdf2, "password", hash);
// Returns true if password matches, false otherwise
```

**Note:** Salt is automatically generated and embedded in the hash output. You only need to store one string.

### Async (for large data or UI responsiveness)

```csharp
string hash = await HashManager.HashAsync(HashType.Pbkdf2, "password");
bool isValid = await HashManager.VerifyAsync(HashType.Pbkdf2, "password", hash);
```

### Binary Data

```csharp
byte[] hash = HashManager.Hash(HashType.Pbkdf2, dataBytes);
bool isValid = HashManager.Verify(HashType.Pbkdf2, dataBytes, hash);
```

## Editor Testing

Open **Tools > Encryption Manager > Test UI** in Unity Editor to test encryption and hashing interactively.

## API Reference

### EncryptionManager

| Method | Description |
|--------|-------------|
| `GetAesAutoKey()` | Generate random AES key, register it, return for saving |
| `RegisterAes(string key)` | Register AES with string key (auto-padded to 32 bytes) |
| `RegisterAes(byte[] key)` | Register AES with byte[] key |
| `GetXorAutoKey()` | Generate random XOR key, register it, return for saving |
| `RegisterXor(byte key)` | Register XOR with specific key |
| `Encrypt(type, data)` | Encrypt string or byte[] |
| `Decrypt(type, data)` | Decrypt string or byte[] |
| `EncryptAsync(type, data)` | Async encrypt (background thread) |
| `DecryptAsync(type, data)` | Async decrypt (background thread) |

### HashManager

| Method | Description |
|--------|-------------|
| `RegisterPbkdf2(iterations)` | Register PBKDF2 with iterations (default 10000) |
| `Hash(type, data)` | Hash string or byte[], returns combined salt+hash |
| `Verify(type, data, hash)` | Verify data against stored hash |
| `HashAsync(type, data)` | Async hash (background thread) |
| `VerifyAsync(type, data, hash)` | Async verify (background thread) |

## Example Code

Create a new script `EMExample.cs` and attach to any GameObject:

```csharp
using UnityEngine;
using vanhaodev.encryptionmanager;

public class EMExample : MonoBehaviour
{
    [Header("XOR Settings")]
    public byte xorKey = 0x5A;

    [Header("AES Settings")]
    public string aesKey = "MySecretKey123";

    void Start()
    {
        string lyrics = "'Cause I know what you like boy\nYou're my chemical hype boy";

        TestXor(lyrics);
        TestAes(lyrics);
        TestHash(lyrics);
    }

    void TestXor(string original)
    {
        Debug.Log("=== XOR Test ===");

        // Register XOR encryption with a single byte key
        EncryptionManager.RegisterXor(xorKey);

        // Encrypt the original string using XOR
        string encrypted = EncryptionManager.Encrypt(EncryptType.Xor, original);
        Debug.Log($"Encrypted: {encrypted}");

        // Decrypt the XOR result back to original
        string decrypted = EncryptionManager.Decrypt(EncryptType.Xor, encrypted);
        Debug.Log($"Decrypted: {decrypted}");
    }

    void TestAes(string original)
    {
        Debug.Log("=== AES Test ===");

        // Register AES encryption with a string key
        EncryptionManager.RegisterAes(aesKey);

        // Encrypt the original string using AES
        string encrypted = EncryptionManager.Encrypt(EncryptType.Aes, original);
        Debug.Log($"Encrypted: {encrypted}");

        // Decrypt the AES result back to original
        string decrypted = EncryptionManager.Decrypt(EncryptType.Aes, encrypted);
        Debug.Log($"Decrypted: {decrypted}");
    }

    void TestHash(string original)
    {
        Debug.Log("=== HASH Test ===");

        // Register PBKDF2 hashing with a specified number of iterations
        HashManager.RegisterPbkdf2(10000);

        // Generate a hash from the original data
        // The result typically contains both salt and hash combined
        string hash = HashManager.Hash(HashType.Pbkdf2, original);
        Debug.Log($"Hash: {hash}");

        // Verify the original data against the generated hash (expected: true)
        bool isValid = HashManager.Verify(HashType.Pbkdf2, original, hash);
        Debug.Log($"Verify (correct): {isValid}");

        // Verify with incorrect data (expected: false)
        bool isInvalid = HashManager.Verify(
            HashType.Pbkdf2,
            "Baby, got me looking so crazy\nppajyeobeorineun daydream",
            hash
        );
        Debug.Log($"Verify (wrong): {isInvalid}");
    }
}
```
