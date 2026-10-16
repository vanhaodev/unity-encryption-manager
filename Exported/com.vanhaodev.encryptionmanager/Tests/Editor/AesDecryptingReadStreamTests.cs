using System;
using System.IO;
using System.Security.Cryptography;
using NUnit.Framework;

namespace vanhaodev.encryptionmanager.tests
{
	/// <summary>The decrypting stream must give exactly the bytes <see cref="AesEncryption.Decrypt"/> gives, for any size and any seek.</summary>
	public class AesDecryptingReadStreamTests
	{
		private static readonly byte[] Key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
		private static readonly AesEncryption Aes = new AesEncryption(Key);
		private static readonly int[] Sizes = { 1, 15, 16, 17, 4095, 4096, 65536, 65537, 131072, 131073, 300000 };

		private static byte[] Plain(int size, int seed)
		{
			var bytes = new byte[size];
			new Random(seed).NextBytes(bytes);
			return bytes;
		}

		[Test]
		public void SequentialRead_MatchesDecrypt([ValueSource(nameof(Sizes))] int size)
		{
			var plain = Plain(size, size);
			var encrypted = Aes.Encrypt(plain);
			using var stream = Aes.OpenDecryptStream(new MemoryStream(encrypted, false));

			Assert.AreEqual(size, stream.Length);
			var read = new byte[size];
			var total = 0;
			int n;
			while ((n = stream.Read(read, total, Math.Min(7919, size - total))) > 0) // odd chunk size crosses block edges
				total += n;
			Assert.AreEqual(size, total);
			CollectionAssert.AreEqual(Aes.Decrypt(encrypted), read);
			Assert.AreEqual(0, stream.Read(read, 0, 10), "read at end returns 0");
		}

		[Test]
		public void RandomSeekAndRead_MatchesPlaintext([ValueSource(nameof(Sizes))] int size)
		{
			var plain = Plain(size, size + 1);
			using var stream = Aes.OpenDecryptStream(new MemoryStream(Aes.Encrypt(plain), false));
			var random = new Random(42);
			var buffer = new byte[200000];

			for (int i = 0; i < 300; i++)
			{
				var start = random.Next(size + 1);
				var count = random.Next(Math.Min(buffer.Length, size - start) + 1);
				stream.Seek(start, SeekOrigin.Begin);
				var n = stream.Read(buffer, 0, count);
				Assert.AreEqual(count, n, $"iteration {i}: start {start} count {count}");
				for (int j = 0; j < n; j++)
					if (buffer[j] != plain[start + j])
						Assert.Fail($"iteration {i}: byte {start + j} differs");
				Assert.AreEqual(start + n, stream.Position);
			}
		}

		[Test]
		public void DataOffset_SkipsCustomHeader()
		{
			var plain = Plain(1000, 5);
			var encrypted = Aes.Encrypt(plain);
			var withHeader = new byte[7 + encrypted.Length];
			Buffer.BlockCopy(encrypted, 0, withHeader, 7, encrypted.Length);

			using var stream = Aes.OpenDecryptStream(new MemoryStream(withHeader, false), dataOffset: 7);
			var read = new byte[1000];
			Assert.AreEqual(1000, stream.Read(read, 0, 1000));
			CollectionAssert.AreEqual(plain, read);
		}

		[Test]
		public void FileOverload_ReadsFromDisk()
		{
			var plain = Plain(70000, 9);
			var path = Path.GetTempFileName();
			try
			{
				File.WriteAllBytes(path, Aes.Encrypt(plain));
				using var stream = Aes.OpenDecryptStream(path);
				var read = new byte[plain.Length];
				var total = 0;
				int n;
				while ((n = stream.Read(read, total, read.Length - total)) > 0)
					total += n;
				CollectionAssert.AreEqual(plain, read);
			}
			finally
			{
				File.Delete(path);
			}
		}

		[Test]
		public void SeekOrigins_Work()
		{
			var plain = Plain(1000, 7);
			using var stream = Aes.OpenDecryptStream(new MemoryStream(Aes.Encrypt(plain), false));
			Assert.AreEqual(990, stream.Seek(-10, SeekOrigin.End));
			Assert.AreEqual(995, stream.Seek(5, SeekOrigin.Current));
			Assert.AreEqual(plain[995], stream.ReadByte());
			stream.Position = 3;
			Assert.AreEqual(plain[3], stream.ReadByte());
			Assert.Throws<IOException>(() => stream.Seek(1001, SeekOrigin.Begin));
			Assert.Throws<IOException>(() => stream.Seek(-1, SeekOrigin.Begin));
		}

		[Test]
		public void WrongKey_ThrowsAtOpen()
		{
			var encrypted = Aes.Encrypt(Plain(5000, 1));
			var wrong = new AesEncryption(new byte[32]);
			var e = Assert.Throws<CryptographicException>(() => wrong.OpenDecryptStream(new MemoryStream(encrypted, false)).Dispose());
			StringAssert.Contains("wrong key", e.Message);
		}

		[Test]
		public void Truncated_OrOddLength_Throw()
		{
			var encrypted = Aes.Encrypt(Plain(100, 2));

			var truncated = new byte[20];
			Buffer.BlockCopy(encrypted, 0, truncated, 0, 20);
			Assert.Throws<InvalidDataException>(() => Aes.OpenDecryptStream(new MemoryStream(truncated, false)).Dispose());

			var oddLength = new byte[encrypted.Length - 1];
			Buffer.BlockCopy(encrypted, 0, oddLength, 0, oddLength.Length);
			Assert.Throws<InvalidDataException>(() => Aes.OpenDecryptStream(new MemoryStream(oddLength, false)).Dispose());
		}

		[Test]
		public void Dispose_ClosesSource_AndRejectsReads()
		{
			var source = new MemoryStream(Aes.Encrypt(Plain(64, 3)), false);
			var stream = Aes.OpenDecryptStream(source);
			stream.Dispose();
			Assert.IsFalse(source.CanRead, "source closed");
			Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[1], 0, 1));
		}
	}
}
