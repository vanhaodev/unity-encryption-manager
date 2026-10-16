using System;
using System.IO;
using System.Security.Cryptography;

namespace vanhaodev.encryptionmanager
{
	/// <summary>
	/// Read-only, seekable view of the plaintext inside data produced by <see cref="AesEncryption.Encrypt"/>
	/// (IV 16 bytes + AES-CBC ciphertext with PKCS7 padding), without ever holding the whole file in memory.<br/>
	/// Blocks are decrypted on demand in 128 KB chunks, so a file of any size costs about 256 KB of managed memory.
	/// Use it for big files: video, audio, AssetBundles (<c>AssetBundle.LoadFromStream</c>), save archives.<br/>
	/// Opening validates length and the padding of the last block, so a wrong key fails at open with ~255/256 odds.
	/// Every public member takes one lock: a single reader may call it from any thread.
	/// </summary>
	public sealed class AesDecryptingReadStream : Stream
	{
		public const int BlockSize = 16;
		public const int IvSize = 16;
		private const int BufferSize = 8192 * BlockSize; // 128 KB of ciphertext per refill

		private readonly object _lock = new object();
		private readonly bool _ownsSource;
		private readonly long _cipherStart; // file offset of the first ciphertext block (after the IV)
		private readonly long _cipherLength;
		private readonly long _plainLength;
		private readonly byte[] _iv = new byte[IvSize];

		private Stream _source;
		private Aes _aes;
		private ICryptoTransform _ecbDecryptor; // reused for every chunk: ECB has no chaining state
		private byte[] _key;
		// Ciphertext chunk with the previous block (the chaining IV) in front of it, and its decrypted form.
		private byte[] _cipherBuffer;
		private byte[] _plainBuffer;
		private long _bufferStart = -1; // plaintext offset of _plainBuffer[0]
		private int _bufferLength;
		private long _position;

		/// <param name="source">Seekable stream holding the encrypted data.</param>
		/// <param name="key">Raw AES key (16, 24 or 32 bytes). The stream copies it and clears the copy on Dispose.</param>
		/// <param name="dataOffset">Where the IV starts in <paramref name="source"/>, for files with a custom header in front.</param>
		/// <param name="ownsSource">Dispose <paramref name="source"/> together with this stream.</param>
		public AesDecryptingReadStream(Stream source, byte[] key, long dataOffset = 0, bool ownsSource = true)
		{
			if (source == null) throw new ArgumentNullException(nameof(source));
			if (key == null) throw new ArgumentNullException(nameof(key));
			if (!source.CanRead || !source.CanSeek) throw new ArgumentException("Source stream must be readable and seekable.", nameof(source));

			_source = source;
			_ownsSource = ownsSource;
			_key = (byte[])key.Clone();
			// CBC decryption done by hand: ECB-decrypt each block, then XOR with the previous ciphertext block.
			_aes = Aes.Create();
			_aes.Mode = CipherMode.ECB;
			_aes.Padding = PaddingMode.None; // padding is handled by hand (Length), blocks are decrypted raw
			_aes.Key = _key;
			_ecbDecryptor = _aes.CreateDecryptor();

			_cipherStart = dataOffset + IvSize;
			_cipherLength = source.Length - _cipherStart;
			if (_cipherLength < BlockSize)
				throw new InvalidDataException($"Encrypted data is truncated ({source.Length} bytes).");
			if (_cipherLength % BlockSize != 0)
				throw new InvalidDataException($"Encrypted data has an invalid length ({source.Length} bytes): not a multiple of the AES block size.");

			ReadExactly(dataOffset, _iv, 0, IvSize);
			_plainLength = _cipherLength - ReadPaddingLength();
		}

		public override bool CanRead => true;
		public override bool CanSeek => true;
		public override bool CanWrite => false;
		public override long Length => _plainLength;

		public override long Position
		{
			get { lock (_lock) return _position; }
			set { Seek(value, SeekOrigin.Begin); }
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			lock (_lock)
			{
				ThrowIfDisposed();
				if (count <= 0 || _position >= _plainLength)
					return 0;

				var remaining = _plainLength - _position;
				if (count > remaining)
					count = (int)remaining;

				var total = 0;
				while (count > 0)
				{
					if (_position < _bufferStart || _position >= _bufferStart + _bufferLength)
						Refill(_position);

					var inBuffer = (int)(_position - _bufferStart);
					var n = Math.Min(count, _bufferLength - inBuffer);
					Buffer.BlockCopy(_plainBuffer, inBuffer, buffer, offset + total, n);
					total += n;
					count -= n;
					_position += n;
				}
				return total;
			}
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			lock (_lock)
			{
				ThrowIfDisposed();
				var target = origin == SeekOrigin.Begin ? offset : origin == SeekOrigin.Current ? _position + offset : _plainLength + offset;
				if (target < 0 || target > _plainLength)
					throw new IOException($"Seek outside the data (position {target}, length {_plainLength}).");
				_position = target;
				return _position;
			}
		}

		public override void Flush() { }
		public override void SetLength(long value) => throw new NotSupportedException();
		public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

		protected override void Dispose(bool disposing)
		{
			lock (_lock)
			{
				if (_source == null)
					return;
				if (_ownsSource)
					_source.Dispose();
				_source = null;
				_ecbDecryptor.Dispose();
				_ecbDecryptor = null;
				_aes.Dispose();
				_aes = null;
				Array.Clear(_key, 0, _key.Length);
				_key = null;
				_cipherBuffer = null;
				_plainBuffer = null;
			}
			base.Dispose(disposing);
		}

		/// <summary>Decrypt the chunk that contains plaintext offset <paramref name="position"/> into the buffers.</summary>
		private void Refill(long position)
		{
			if (_cipherBuffer == null)
			{
				_cipherBuffer = new byte[BufferSize + BlockSize];
				_plainBuffer = new byte[BufferSize];
			}

			var blockIndex = position / BlockSize;
			var start = blockIndex * BlockSize;
			var count = (int)Math.Min(BufferSize, _cipherLength - start);

			if (blockIndex == 0)
			{
				Buffer.BlockCopy(_iv, 0, _cipherBuffer, 0, BlockSize);
				ReadExactly(_cipherStart, _cipherBuffer, BlockSize, count);
			}
			else
			{
				// One read: previous block (chaining IV) followed by the chunk itself.
				ReadExactly(_cipherStart + start - BlockSize, _cipherBuffer, 0, count + BlockSize);
			}

			DecryptBlocks(_cipherBuffer, count, _plainBuffer);
			_bufferStart = start;
			_bufferLength = (int)Math.Min(count, _plainLength - start); // last chunk: drop the padding
		}

		/// <summary>
		/// CBC-decrypt <paramref name="count"/> bytes of <paramref name="cipher"/> starting at index 16, where
		/// cipher[0..16] is the previous ciphertext block: plain_i = ECB_dec(C_i) XOR C_(i-1).
		/// </summary>
		private void DecryptBlocks(byte[] cipher, int count, byte[] plain)
		{
			var done = _ecbDecryptor.TransformBlock(cipher, BlockSize, count, plain, 0);
			if (done < count)
			{
				// Not expected for ECB without padding, but some implementations hold back a block: flush it and
				// start a fresh transform, since a finalized one cannot be reused.
				var rest = _ecbDecryptor.TransformFinalBlock(cipher, BlockSize + done, count - done);
				Buffer.BlockCopy(rest, 0, plain, done, rest.Length);
				_ecbDecryptor.Dispose();
				_ecbDecryptor = _aes.CreateDecryptor();
			}

			// plain[i] holds ECB_dec(C_i); the previous ciphertext block sits 16 bytes earlier in 'cipher'.
			for (int i = 0; i < count; i++)
				plain[i] ^= cipher[i];
		}

		/// <summary>Decrypt only the last block to read its PKCS7 padding (1..16). Anything else means wrong key or damage.</summary>
		private int ReadPaddingLength()
		{
			var lastIndex = _cipherLength / BlockSize - 1;
			var cipher = new byte[2 * BlockSize];
			var plain = new byte[BlockSize];
			if (lastIndex == 0)
			{
				Buffer.BlockCopy(_iv, 0, cipher, 0, BlockSize);
				ReadExactly(_cipherStart, cipher, BlockSize, BlockSize);
			}
			else
			{
				ReadExactly(_cipherStart + (lastIndex - 1) * BlockSize, cipher, 0, 2 * BlockSize);
			}
			DecryptBlocks(cipher, BlockSize, plain);

			int pad = plain[BlockSize - 1];
			var valid = pad >= 1 && pad <= BlockSize;
			for (int i = BlockSize - pad; valid && i < BlockSize; i++)
				valid = plain[i] == pad;
			if (!valid)
				throw new CryptographicException("Cannot decrypt: wrong key or corrupted data.");
			return pad;
		}

		private void ReadExactly(long fileOffset, byte[] buffer, int offset, int count)
		{
			_source.Seek(fileOffset, SeekOrigin.Begin);
			while (count > 0)
			{
				var n = _source.Read(buffer, offset, count);
				if (n <= 0)
					throw new EndOfStreamException($"Encrypted data ended early at {fileOffset}: truncated.");
				offset += n;
				count -= n;
			}
		}

		private void ThrowIfDisposed()
		{
			if (_source == null)
				throw new ObjectDisposedException(nameof(AesDecryptingReadStream));
		}
	}
}
