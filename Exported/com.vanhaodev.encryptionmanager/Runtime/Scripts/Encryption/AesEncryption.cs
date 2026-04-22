using System;
using System.Security.Cryptography;

namespace vanhaodev.encryptionmanager
{
	public class AesEncryption : IEncryption
	{
		private readonly byte[] _key;

		public AesEncryption(byte[] key)
		{
			_key = key;
		}

		/// <summary>Encrypt with random IV prepended to output.</summary>
		public byte[] Encrypt(byte[] data)
		{
			using var aes = Aes.Create();
			aes.Key = _key;
			aes.GenerateIV();

			using var encryptor = aes.CreateEncryptor();
			var ciphertext = encryptor.TransformFinalBlock(data, 0, data.Length);

			// Combine: IV (16 bytes) + ciphertext
			var result = new byte[16 + ciphertext.Length];
			Array.Copy(aes.IV, 0, result, 0, 16);
			Array.Copy(ciphertext, 0, result, 16, ciphertext.Length);
			return result;
		}

		/// <summary>Decrypt by extracting IV from first 16 bytes.</summary>
		public byte[] Decrypt(byte[] data)
		{
			// Extract IV and ciphertext
			var iv = new byte[16];
			var ciphertext = new byte[data.Length - 16];
			Array.Copy(data, 0, iv, 0, 16);
			Array.Copy(data, 16, ciphertext, 0, ciphertext.Length);

			using var aes = Aes.Create();
			aes.Key = _key;
			aes.IV = iv;

			using var decryptor = aes.CreateDecryptor();
			return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
		}
	}
}