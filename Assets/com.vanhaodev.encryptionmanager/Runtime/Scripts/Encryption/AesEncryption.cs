using System;
using System.IO;
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

		/// <summary>
		/// Decrypt on the fly while reading, without loading the whole data into memory. Use it for big files
		/// (video, audio, AssetBundles, save archives). Same format as <see cref="Decrypt"/>: IV + ciphertext.
		/// </summary>
		/// <param name="source">Seekable stream holding data produced by <see cref="Encrypt"/>.</param>
		/// <param name="dataOffset">Where the IV starts in <paramref name="source"/>, for files with a custom header in front.</param>
		/// <param name="ownsSource">Dispose <paramref name="source"/> together with the returned stream.</param>
		/// <returns>Read-only, seekable plaintext stream. Keep it open while the plaintext is in use.</returns>
		/// <exception cref="CryptographicException">Wrong key (detected with ~255/256 odds at open).</exception>
		/// <exception cref="InvalidDataException">Data too short or not a multiple of the AES block size.</exception>
		public Stream OpenDecryptStream(Stream source, long dataOffset = 0, bool ownsSource = true)
		{
			return new AesDecryptingReadStream(source, _key, dataOffset, ownsSource);
		}

		/// <summary>Decrypt a file on the fly while reading. See <see cref="OpenDecryptStream(Stream, long, bool)"/>.</summary>
		public Stream OpenDecryptStream(string path, long dataOffset = 0)
		{
			var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.RandomAccess);
			try
			{
				return new AesDecryptingReadStream(file, _key, dataOffset, ownsSource: true);
			}
			catch
			{
				file.Dispose();
				throw;
			}
		}
	}
}