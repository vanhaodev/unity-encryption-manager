namespace vanhaodev.encryptionmanager
{
	public class XorEncryption : IEncryption
	{
		private readonly byte _key;

		public XorEncryption(byte key)
		{
			_key = key;
		}

		public byte[] Encrypt(byte[] data)
		{
			var result = new byte[data.Length];

			for (int i = 0; i < data.Length; i++)
				result[i] = (byte)(data[i] ^ _key);

			return result;
		}

		public byte[] Decrypt(byte[] data) => Encrypt(data);
	}
}