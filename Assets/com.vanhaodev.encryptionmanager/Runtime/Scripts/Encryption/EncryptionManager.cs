using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace vanhaodev.encryptionmanager
{
	/// <summary>
	/// EncryptionManager.RegisterAes("mySecretKey");<br/>
	/// var encrypted = EncryptionManager.Encrypt(EncryptType.Aes, data);<br/>
	/// var decrypted = EncryptionManager.Decrypt(EncryptType.Aes, encrypted);<br/>
	/// </summary>
	public static class EncryptionManager
	{
		private static readonly Dictionary<EncryptType, IEncryption> _map = new();

		/// <summary>Register a custom encryption implementation.</summary>
		public static void Register(EncryptType type, IEncryption encryption)
		{
			_map[type] = encryption;
		}

		/// <summary>Encrypt binary data. Returns encrypted bytes.</summary>
		public static byte[] Encrypt(EncryptType type, byte[] data)
		{
			return _map[type].Encrypt(data);
		}

		/// <summary>Decrypt binary data. Returns original bytes.</summary>
		public static byte[] Decrypt(EncryptType type, byte[] data)
		{
			return _map[type].Decrypt(data);
		}

		/// <summary>Encrypt binary data on background thread. Use for large data to avoid freezing.</summary>
		public static Task<byte[]> EncryptAsync(EncryptType type, byte[] data)
		{
			return Task.Run(() => _map[type].Encrypt(data));
		}

		/// <summary>Decrypt binary data on background thread. Use for large data to avoid freezing.</summary>
		public static Task<byte[]> DecryptAsync(EncryptType type, byte[] data)
		{
			return Task.Run(() => _map[type].Decrypt(data));
		}

		/// <summary>Encrypt text string. Returns Base64 encoded string.</summary>
		public static string Encrypt(EncryptType type, string text)
		{
			var data = Encoding.UTF8.GetBytes(text);
			return Convert.ToBase64String(_map[type].Encrypt(data));
		}

		/// <summary>Decrypt Base64 encoded string. Returns original text.</summary>
		public static string Decrypt(EncryptType type, string base64)
		{
			var data = Convert.FromBase64String(base64);
			return Encoding.UTF8.GetString(_map[type].Decrypt(data));
		}

		/// <summary>Encrypt text string on background thread. Returns Base64 encoded string.</summary>
		public static async Task<string> EncryptAsync(EncryptType type, string text)
		{
			var data = Encoding.UTF8.GetBytes(text);
			var encrypted = await Task.Run(() => _map[type].Encrypt(data));
			return Convert.ToBase64String(encrypted);
		}

		/// <summary>Decrypt Base64 encoded string on background thread. Returns original text.</summary>
		public static async Task<string> DecryptAsync(EncryptType type, string base64)
		{
			var data = Convert.FromBase64String(base64);
			var decrypted = await Task.Run(() => _map[type].Decrypt(data));
			return Encoding.UTF8.GetString(decrypted);
		}

		/// <summary>Generate random XOR key, register it, and return for saving.</summary>
		public static byte GetXorAutoKey()
		{
			var key = (byte)RandomNumberGenerator.GetInt32(1, 256);
			_map[EncryptType.Xor] = new XorEncryption(key);
			return key;
		}

		/// <summary>Register XOR with your own key.</summary>
		public static void RegisterXor(byte key)
		{
			_map[EncryptType.Xor] = new XorEncryption(key);
		}

		/// <summary>Generate random AES key, register it, and return for saving.</summary>
		public static byte[] GetAesAutoKey()
		{
			using var aes = Aes.Create();
			aes.GenerateKey();
			_map[EncryptType.Aes] = new AesEncryption(aes.Key);
			return aes.Key;
		}

		/// <summary>Register AES with your own byte[] key.</summary>
		public static void RegisterAes(byte[] key)
		{
			_map[EncryptType.Aes] = new AesEncryption(key);
		}

		/// <summary>Register AES with string key (auto-padded/trimmed to 32 bytes).</summary>
		public static void RegisterAes(string key)
		{
			var bytes = Encoding.UTF8.GetBytes(key);
			var keyBytes = new byte[32];
			Array.Copy(bytes, keyBytes, Math.Min(bytes.Length, 32));
			_map[EncryptType.Aes] = new AesEncryption(keyBytes);
		}
	}
}