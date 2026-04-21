using System;
using System.Linq;
using System.Security.Cryptography;

namespace vanhaodev.encryptionmanager
{
	public class Pbkdf2Hash : IHash
	{
		private readonly int _iterations;
		private readonly int _hashSize;
		private readonly int _saltSize;

		/// <param name="iterations">Higher = slower but more secure. Default 10000.</param>
		/// <param name="hashSize">Output hash size in bytes. Default 32 (256-bit).</param>
		/// <param name="saltSize">Salt size in bytes. Default 16 (128-bit).</param>
		public Pbkdf2Hash(int iterations = 10000, int hashSize = 32, int saltSize = 16)
		{
			_iterations = iterations;
			_hashSize = hashSize;
			_saltSize = saltSize;
		}

		/// <summary>Compute hash with auto-generated salt. Returns combined: salt + hash.</summary>
		public byte[] Compute(byte[] data)
		{
			var salt = new byte[_saltSize];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(salt);
			}

			using var pbkdf2 = new Rfc2898DeriveBytes(data, salt, _iterations, HashAlgorithmName.SHA256);
			var hash = pbkdf2.GetBytes(_hashSize);

			// Combine: salt + hash
			var combined = new byte[_saltSize + _hashSize];
			Array.Copy(salt, 0, combined, 0, _saltSize);
			Array.Copy(hash, 0, combined, _saltSize, _hashSize);
			return combined;
		}

		/// <summary>Verify data against combined salt+hash.</summary>
		public bool Verify(byte[] data, byte[] combined)
		{
			// Extract salt and hash
			var salt = new byte[_saltSize];
			var hash = new byte[_hashSize];
			Array.Copy(combined, 0, salt, 0, _saltSize);
			Array.Copy(combined, _saltSize, hash, 0, _hashSize);

			using var pbkdf2 = new Rfc2898DeriveBytes(data, salt, _iterations, HashAlgorithmName.SHA256);
			var computed = pbkdf2.GetBytes(_hashSize);
			return computed.SequenceEqual(hash);
		}
	}
}
