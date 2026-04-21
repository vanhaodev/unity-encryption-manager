namespace vanhaodev.encryptionmanager
{
	public interface IEncryption
	{
		byte[] Encrypt(byte[] data);
		byte[] Decrypt(byte[] data);
	}
}