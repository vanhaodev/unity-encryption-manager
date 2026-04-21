using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace vanhaodev.encryptionmanager
{
	public static class HashManager
	{
		private static readonly Dictionary<HashType, IHash> _map = new();

		/// <summary>Register a custom hash implementation.</summary>
		public static void Register(HashType type, IHash hash)
		{
			_map[type] = hash;
		}

		/// <summary>Register PBKDF2 with default settings (10000 iterations).</summary>
		public static void RegisterPbkdf2(int iterations = 10000)
		{
			_map[HashType.Pbkdf2] = new Pbkdf2Hash(iterations);
		}

		/// <summary>Hash binary data. Returns combined salt+hash bytes.</summary>
		public static byte[] Hash(HashType type, byte[] data)
		{
			return _map[type].Compute(data);
		}

		/// <summary>Verify binary data against combined salt+hash.</summary>
		public static bool Verify(HashType type, byte[] data, byte[] combined)
		{
			return _map[type].Verify(data, combined);
		}

		/// <summary>Hash string. Returns combined salt+hash as Base64.</summary>
		public static string Hash(HashType type, string text)
		{
			var data = Encoding.UTF8.GetBytes(text);
			var combined = _map[type].Compute(data);
			return Convert.ToBase64String(combined);
		}

		/// <summary>Verify string against combined salt+hash (Base64).</summary>
		public static bool Verify(HashType type, string text, string combinedBase64)
		{
			var data = Encoding.UTF8.GetBytes(text);
			var combined = Convert.FromBase64String(combinedBase64);
			return _map[type].Verify(data, combined);
		}

		/// <summary>Hash binary data on background thread.</summary>
		public static Task<byte[]> HashAsync(HashType type, byte[] data)
		{
			return Task.Run(() => _map[type].Compute(data));
		}

		/// <summary>Verify binary data on background thread.</summary>
		public static Task<bool> VerifyAsync(HashType type, byte[] data, byte[] combined)
		{
			return Task.Run(() => _map[type].Verify(data, combined));
		}

		/// <summary>Hash string on background thread.</summary>
		public static async Task<string> HashAsync(HashType type, string text)
		{
			var data = Encoding.UTF8.GetBytes(text);
			var combined = await Task.Run(() => _map[type].Compute(data));
			return Convert.ToBase64String(combined);
		}

		/// <summary>Verify string on background thread.</summary>
		public static Task<bool> VerifyAsync(HashType type, string text, string combinedBase64)
		{
			var data = Encoding.UTF8.GetBytes(text);
			var combined = Convert.FromBase64String(combinedBase64);
			return Task.Run(() => _map[type].Verify(data, combined));
		}
	}
}
