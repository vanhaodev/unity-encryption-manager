#if UNITY_EDITOR
using UnityEngine;
using vanhaodev.encryptionmanager;

namespace vanhaodev.encryptionmanager.tests
{
	public class EncryptionTest : MonoBehaviour
	{
	void Start()
	{
		TestXorString();
		TestAesString();
		TestAesStringWithCustomKey();
	}

	void TestXorString()
	{
		Debug.Log("=== XOR String Test ===");

		var key = EncryptionManager.GetXorAutoKey();
		Debug.Log($"Generated key: {key}");

		var original = "Hello World!";
		var encrypted = EncryptionManager.Encrypt(EncryptType.Xor, original);
		var decrypted = EncryptionManager.Decrypt(EncryptType.Xor, encrypted);

		Debug.Log($"Original: {original}");
		Debug.Log($"Encrypted: {encrypted}");
		Debug.Log($"Decrypted: {decrypted}");
		Debug.Log($"XOR Test: {(original == decrypted ? "PASS" : "FAIL")}");
	}

	void TestAesString()
	{
		Debug.Log("=== AES String Test (Auto Key) ===");

		var key = EncryptionManager.GetAesAutoKey();
		Debug.Log($"Generated key length: {key.Length} (IV auto-generated per encrypt)");

		var original = "Hello AES Encryption!";
		var encrypted = EncryptionManager.Encrypt(EncryptType.Aes, original);
		var decrypted = EncryptionManager.Decrypt(EncryptType.Aes, encrypted);

		Debug.Log($"Original: {original}");
		Debug.Log($"Encrypted: {encrypted}");
		Debug.Log($"Decrypted: {decrypted}");
		Debug.Log($"AES Auto Test: {(original == decrypted ? "PASS" : "FAIL")}");
	}

	void TestAesStringWithCustomKey()
	{
		Debug.Log("=== AES String Test (Custom Key) ===");

		EncryptionManager.RegisterAes("mySecretKey123");

		var original = "Hello Custom AES!";
		var encrypted = EncryptionManager.Encrypt(EncryptType.Aes, original);
		var decrypted = EncryptionManager.Decrypt(EncryptType.Aes, encrypted);

		Debug.Log($"Original: {original}");
		Debug.Log($"Encrypted: {encrypted}");
		Debug.Log($"Decrypted: {decrypted}");
		Debug.Log($"AES Custom Test: {(original == decrypted ? "PASS" : "FAIL")}");
	}
}
}
#endif
