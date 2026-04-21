#if UNITY_EDITOR
using UnityEngine;
using vanhaodev.encryptionmanager;

namespace vanhaodev.encryptionmanager.tests
{
	public class HashTest : MonoBehaviour
	{
		void Start()
		{
			TestPbkdf2String();
			TestPbkdf2Verify();
		}

		void TestPbkdf2String()
		{
			Debug.Log("=== PBKDF2 String Test ===");

			HashManager.RegisterPbkdf2();

			var password = "MySecretPassword123";
			var hash = HashManager.Hash(HashType.Pbkdf2, password);

			Debug.Log($"Password: {password}");
			Debug.Log($"Hash (salt+hash combined): {hash}");
			Debug.Log("PBKDF2 Hash Test: PASS");
		}

		void TestPbkdf2Verify()
		{
			Debug.Log("=== PBKDF2 Verify Test ===");

			var password = "MySecretPassword123";
			var wrongPassword = "WrongPassword";

			var hash = HashManager.Hash(HashType.Pbkdf2, password);

			var validResult = HashManager.Verify(HashType.Pbkdf2, password, hash);
			var invalidResult = HashManager.Verify(HashType.Pbkdf2, wrongPassword, hash);

			Debug.Log($"Correct password verify: {(validResult ? "VALID" : "INVALID")}");
			Debug.Log($"Wrong password verify: {(invalidResult ? "VALID" : "INVALID")}");
			Debug.Log($"PBKDF2 Verify Test: {(validResult && !invalidResult ? "PASS" : "FAIL")}");
		}
	}
}
#endif
